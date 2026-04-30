#include "plugin.hpp"

static Julie                  _julie;
Julie                        *julie = &_julie;
yed_plugin                   *Self;
static array_t                prompt_hist;
static yed_cmd_line_readline  prompt_readline;

Binding_Registry& Binding_Registry::get() {
    static Binding_Registry registry;
    return registry;
}

void Binding_Registry::register_binding(const std::string &name, Binding_Fn fn) {
    this->bindings[name] = fn;
}

Binding_Registrar::Binding_Registrar(const std::string &name, Binding_Registry::Binding_Fn fn) {
    Binding_Registry::get().register_binding(name, fn);
}

void Interp_Message::destroy() {
    switch (this->type) {
        case INTERP_MESSAGE_STOP:
            break;

        case INTERP_MESSAGE_EVAL:
            free(this->eval.code);
            break;

        case INTERP_MESSAGE_CMD:
            free(this->cmd.cmd);
            for (int i = 0; i < this->cmd.n_args; i += 1) {
                free(this->cmd.args[i]);
            }
            free(this->cmd.args);
            break;

        case INTERP_MESSAGE_EVENT:
            break;
    }
}

struct Interp_Thread_Data {
    bool            initialized     = false;
    Julie_String_ID sid_config_path = nullptr;
    Julie_String_ID sid_CONFIG_PATH = nullptr;
    Julie_String_ID sid_CURSOR_WORD = nullptr;
    Julie_String_ID sid_BUFFNAME    = nullptr;
    Julie_String_ID sid_LINE        = nullptr;
    Julie_String_ID sid_LINENO      = nullptr;
    Julie_String_ID sid_COLNO       = nullptr;
    Julie_String_ID sid_NUMFRAMES  = nullptr;
    Julie_String_ID sid_FRAME       = nullptr;
    Julie_String_ID sid_EVENT       = nullptr;
};

thread_local Interp_Thread_Data interp_thread_data;
thread_local Julie_Interp      *tl_interp = nullptr;

static void direct_eval_string(Julie_Interp *interp, const char *code) {
    Julie_Array        *roots = JULIE_ARRAY_INIT;
    unsigned long long  err_line;
    unsigned long long  err_col;

    Julie_Status status = julie_parse_roots(interp, &roots, code, strlen(code), &err_line, &err_col, 1);
    if (status != JULIE_SUCCESS) {
        julie_make_parse_error(interp, err_line, err_col, status);
        return;
    }

    if (julie_array_len(roots) == 0) {
        julie_array_free(roots);
        return;
    }

    Julie_Value *code_val;
    if (julie_array_len(roots) == 1) {
        code_val = (Julie_Value*)julie_array_elem(roots, 0);
    } else {
        Julie_Value *do_list = julie_list_value(interp);
        Julie_Value *do_sym  = julie_symbol_value(interp, julie_get_string_id(interp, "do"));
        JULIE_ARRAY_PUSH(do_list->list, do_sym);
        Julie_Value *it;
        ARRAY_FOR_EACH(roots, it) {
            JULIE_ARRAY_PUSH(do_list->list, it);
        }
        code_val = do_list;
    }

    Julie_Value *apply = julie_list_value(interp);
    JULIE_ARRAY_PUSH(apply->list, code_val);

    julie_array_free(roots);

    Julie_Value *result;
    status = julie_eval(interp, apply, &result);
    if (status == JULIE_SUCCESS) {
        julie_free_value(interp, result);
    }

    julie_free_value(interp, apply);
}

static void direct_eval_cmd(Julie_Interp *interp, const char *cmd, int n_args, char **args) {
    Julie_Value *lookup = julie_lookup(interp, julie_get_string_id(interp, cmd));

    if (lookup == NULL || lookup->type != JULIE_FN) {
        return;
    }

    Julie_Value *list = julie_list_value(interp);
    JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, cmd)));
    for (int i = 0; i < n_args; i += 1) {
        JULIE_ARRAY_PUSH(list->list, julie_string_value(interp, args[i]));
    }
    Julie_Value *apply = julie_list_value(interp);
    JULIE_ARRAY_PUSH(apply->list, list);

    Julie_Value *result;
    Julie_Status status = julie_eval(interp, apply, &result);
    if (status == JULIE_SUCCESS) {
        julie_free_value(interp, result);
    }

    julie_free_value(interp, apply);
}

static void direct_eval_event(Julie_Interp *interp, int kind) {
    const char *list_name = NULL;
    switch (kind) {
        case EVENT_KEY_PRESSED:         list_name = "@on-key";                  break;
        case EVENT_FRAME_ACTIVATED:     list_name = "@on-frame-activated";      break;
        case EVENT_BUFFER_POST_LOAD:    list_name = "@on-buffer-load";          break;
        case EVENT_FRAME_PRE_DELETE:    list_name = "@on-frame-delete";         break;
        case EVENT_CURSOR_POST_MOVE:    list_name = "@on-cursor-move";          break;
        case EVENT_BUFFER_FOCUSED:      list_name = "@on-buffer-focused";       break;
        case EVENT_BUFFER_PRE_FOCUS:    list_name = "@on-pre-buffer-focus";     break;
        case EVENT_PRE_DRAW_EVERYTHING: list_name = "@on-pre-draw-everything";  break;
        default:                                                                break;
    }
    if (list_name != NULL) {
        Julie_Value *lookup = julie_lookup(interp, julie_get_string_id(interp, list_name));
        if (lookup != NULL && lookup->type == JULIE_LIST) {
            Julie_Value *it;
            ARRAY_FOR_EACH(lookup->list, it) {
                Julie_Value *result = NULL;
                julie_eval(interp, it, &result);
                if (result != NULL) {
                    julie_free_value(interp, result);
                }
            }
        }
    }
}

Message_Queue<Interp_Message>& Julie::get_interp_messages() {
    return this->interp_messages;
}

Message_Queue<Editor_Message>& Julie::get_editor_messages() {
    return this->editor_messages;
}

static void interp_output_cb(const char *s, int n_bytes) {
    Editor_Message msg;

    msg.type = EDITOR_MESSAGE_JULIE_OUTPUT;
    msg.output.str = (char*)malloc(n_bytes + 1);
    memcpy(msg.output.str, s, n_bytes);
    msg.output.str[n_bytes] = 0;

    julie->get_editor_messages().push(msg);
    julie->request_pump();
}

static void interp_error_cb(Julie_Error_Info *info) {
    char                  *s;
    char                   buff[1024];
    unsigned               i;
    Julie_Backtrace_Entry *it;

    s = julie_get_pretty_error_string(info, "", "", "");
    interp_output_cb(s, strlen(s));

    /* Extract the short message (first line of pretty error string). */
    char short_msg[256];
    {
        char *nl = strchr(s, '\n');
        size_t len = nl ? (size_t)(nl - s) : strlen(s);
        if (len >= sizeof(short_msg)) { len = sizeof(short_msg) - 1; }
        memcpy(short_msg, s, len);
        short_msg[len] = '\0';
    }
    free(s);

    snprintf(buff, sizeof(buff), "\n");
    interp_output_cb(buff, strlen(buff));

    /* Walk backtrace — emit to output and find innermost real file location. */
    const char *err_file = NULL;
    unsigned long long err_line = 0, err_col = 0;

    i = 0;
    while ((it = julie_bt_entry(info->interp, i)) != NULL) {
        s = julie_to_string(info->interp, it->fn, 0);
        snprintf(buff, sizeof(buff), "    %s:%llu:%llu %s\n",
                it->file_id == NULL ? "<?>" : julie_get_cstring(it->file_id),
                it->line,
                it->col,
                s);
        free(s);
        interp_output_cb(buff, strlen(buff));

        if (err_file == NULL && it->file_id != NULL) {
            err_file = julie_get_cstring(it->file_id);
            err_line = it->line;
            err_col  = it->col;
        }

        i += 1;
    }

    if (info->status == JULIE_ERR_ERROR_VALUE) {
        Julie_Value *key = julie_symbol_value(info->interp, julie_get_string_id(info->interp, "'__message__"));
        Julie_Value *message = julie_object_get_field(info->thrown.error_value, key);
        julie_free_value(info->interp, key);

        if (message != NULL) {
            s = julie_to_string(info->interp, message, JULIE_NO_QUOTE);
            snprintf(buff, sizeof(buff), "error thrown: %s\n", s);
            free(s);
            interp_output_cb(buff, strlen(buff));
        } else {
            snprintf(buff, sizeof(buff), "error thrown:\n");
            interp_output_cb(buff, strlen(buff));
        }

        key = julie_symbol_value(info->interp, julie_get_string_id(info->interp, "'__backtrace__"));
        Julie_Value *bt = julie_object_get_field(info->thrown.error_value, key);
        julie_free_value(info->interp, key);

        Julie_Value *frame = NULL;
        if (bt != NULL && bt->type == JULIE_LIST) {
            ARRAY_FOR_EACH(bt->list, frame) {
                s = julie_to_string(info->interp, frame, JULIE_NO_QUOTE);
                snprintf(buff, sizeof(buff), "    %s\n", s);
                free(s);
                interp_output_cb(buff, strlen(buff));
            }
        }
    }

    /* Queue error notification for the yed thread. */
    {
        Editor_Message msg;
        msg.type         = EDITOR_MESSAGE_JULIE_ERROR;
        msg.error.file   = err_file ? strdup(err_file) : NULL;
        msg.error.message= strdup(short_msg);
        msg.error.line   = (int)err_line;
        msg.error.col    = (int)err_col;
        julie->get_editor_messages().push(msg);
        julie->request_pump();
    }

    julie_free_error_info(info);
}

bool Julie::current_thread_owns_yed_context() {
    return this->yed_context_owner.load() == std::this_thread::get_id();
}

void Julie::set_yed_context_owner(std::thread::id id) {
    this->yed_context_owner.store(id);
}

static void init_thread_data(Julie_Interp *interp) {
    if (interp_thread_data.initialized) { return; }

    auto do_init = [&]() {
        interp_thread_data.sid_config_path = julie_get_string_id(interp, get_config_path());
        interp_thread_data.sid_CONFIG_PATH = julie_get_string_id(interp, "$CONFIG-PATH");
        interp_thread_data.sid_BUFFNAME    = julie_get_string_id(interp, "$BUFFNAME");
        interp_thread_data.sid_CURSOR_WORD = julie_get_string_id(interp, "$CURSOR-WORD");
        interp_thread_data.sid_LINE        = julie_get_string_id(interp, "$LINE");
        interp_thread_data.sid_LINENO      = julie_get_string_id(interp, "$LINENO");
        interp_thread_data.sid_COLNO       = julie_get_string_id(interp, "$COLNO");
        interp_thread_data.sid_NUMFRAMES   = julie_get_string_id(interp, "$NUMFRAMES");
        interp_thread_data.sid_FRAME       = julie_get_string_id(interp, "$FRAME");
        interp_thread_data.sid_EVENT       = julie_get_string_id(interp, "$EVENT");
        interp_thread_data.initialized     = true;
    };

    if (julie->current_thread_owns_yed_context()) {
        do_init();
    } else {
        auto lock = julie->pause_yed_thread_scoped();
        do_init();
    }
}

static Julie_Status interp_eval_custom_symbol(Julie_Interp *interp, Julie_Value *value, Julie_Value **result) {
    Julie_String_ID id = julie_value_string_id(interp, value);

    init_thread_data(interp);

    if (id == interp_thread_data.sid_CONFIG_PATH) {
        *result = julie_interned_string_value(interp, interp_thread_data.sid_config_path);
    } else if (id == interp_thread_data.sid_BUFFNAME) {
        auto lock = julie->pause_yed_thread_scoped();
        if (ys->active_frame != NULL && ys->active_frame->buffer != NULL) {
            *result = julie_string_value(interp, ys->active_frame->buffer->name);
        } else {
            *result = julie_nil_value(interp);
        }
    } else if (id == interp_thread_data.sid_CURSOR_WORD) {
        auto lock = julie->pause_yed_thread_scoped();
        char *word = yed_word_under_cursor();
        if (word != NULL) {
            *result = julie_string_value_giveaway(interp, word);
        } else {
            *result = julie_nil_value(interp);
        }
    } else if (id == interp_thread_data.sid_LINE) {
        if (ys->active_frame != NULL && ys->active_frame->buffer != NULL) {
            auto line = yed_buff_get_line(ys->active_frame->buffer, ys->active_frame->cursor_line);
            array_zero_term(line->chars);

            *result = julie_string_value_known_size(interp, (const char*)line->chars.data, line->chars.used);
        } else {
            *result = julie_nil_value(interp);
        }
    } else if (id == interp_thread_data.sid_LINENO) {
        auto lock = julie->pause_yed_thread_scoped();

        if (ys->active_frame != NULL) {
            *result = julie_sint_value(interp, ys->active_frame->cursor_line);
        } else {
            *result = julie_sint_value(interp, 0);
        }
    } else if (id == interp_thread_data.sid_COLNO) {
        auto lock = julie->pause_yed_thread_scoped();

        if (ys->active_frame != NULL) {
            *result = julie_sint_value(interp, ys->active_frame->cursor_col);
        } else {
            *result = julie_sint_value(interp, 0);
        }
    } else if (id == interp_thread_data.sid_NUMFRAMES) {
        auto lock = julie->pause_yed_thread_scoped();
        *result = julie_sint_value(interp, array_len(ys->frames));
    } else if (id == interp_thread_data.sid_FRAME) {
        auto lock = julie->pause_yed_thread_scoped();

        int i = 0;
        yed_frame **fit = NULL;
        array_traverse(ys->frames, fit) {
            if (*fit == ys->active_frame) {
                *result = julie_sint_value(interp, i);
                break;
            }
            i += 1;
        }

        if (*result == NULL) {
            *result = julie_nil_value(interp);
        }
    } else if (id == interp_thread_data.sid_EVENT) {
        auto lock = julie->pause_yed_thread_scoped();
        *result = julie->get_event_object(interp);
    }

    return JULIE_SUCCESS;
}

bool Julie::is_in_teardown() { return this->teardown; }

static Julie_Status interp_pre_eval_cb(Julie_Interp *interp, Julie_Value *value, Julie_Value **result) {
    if (julie->is_in_teardown()) { return JULIE_ERR_EVAL_CANCELLED; }

    if (value->type == JULIE_SYMBOL) {
        return interp_eval_custom_symbol(interp, value, result);
    }

    return JULIE_SUCCESS;
}


static void interp_thread_main() {
    Julie_Interp *interp = julie_init_interp();
    tl_interp = interp;

    julie_set_error_callback(interp,  interp_error_cb);
    julie_set_output_callback(interp, interp_output_cb);
    julie_set_eval_callback(interp,   interp_pre_eval_cb);

    Julie_Value *list = julie_list_value(interp);
    julie_bind(interp, julie_get_string_id(interp, "@on-key"), &list);

    init_thread_data(interp);

    for (auto &binding : Binding_Registry::get().bindings) {
        julie_bind_fn(interp, julie_get_string_id(interp, binding.first.c_str()), binding.second);
    }

    Julie_Value *on_frame_activated_list = julie_list_value(interp);
    julie_bind(interp, julie_get_string_id(interp, "@on-frame-activated"), &on_frame_activated_list);
    Julie_Value *on_buffer_load_list = julie_list_value(interp);
    julie_bind(interp, julie_get_string_id(interp, "@on-buffer-load"), &on_buffer_load_list);
    Julie_Value *on_frame_delete_list = julie_list_value(interp);
    julie_bind(interp, julie_get_string_id(interp, "@on-frame-delete"), &on_frame_delete_list);
    Julie_Value *on_cursor_move_list = julie_list_value(interp);
    julie_bind(interp, julie_get_string_id(interp, "@on-cursor-move"), &on_cursor_move_list);
    Julie_Value *on_buffer_focused_list = julie_list_value(interp);
    julie_bind(interp, julie_get_string_id(interp, "@on-buffer-focused"), &on_buffer_focused_list);
    Julie_Value *on_pre_buffer_focus_list = julie_list_value(interp);
    julie_bind(interp, julie_get_string_id(interp, "@on-pre-buffer-focus"), &on_pre_buffer_focus_list);
    Julie_Value *on_pre_draw_everything_list = julie_list_value(interp);
    julie_bind(interp, julie_get_string_id(interp, "@on-pre-draw-everything"), &on_pre_draw_everything_list);

    while (true) {
        Interp_Message msg = julie->get_interp_messages().pop();

        switch (msg.type) {
            case INTERP_MESSAGE_STOP: goto out;

            case INTERP_MESSAGE_EVAL: {
                direct_eval_string(interp, msg.eval.code);
                break;
            }

            case INTERP_MESSAGE_CMD: {
                direct_eval_cmd(interp, msg.cmd.cmd, msg.cmd.n_args, msg.cmd.args);
                break;
            }

            case INTERP_MESSAGE_EVENT: {
                direct_eval_event(interp, msg.event.kind);
                break;
            }
        }

        msg.destroy();

        {
            std::unique_lock lock(julie->eval_mtx);
            julie->n_pending_eval -= 1;
        }
        julie->eval_cond.notify_all();
    }

out:;
    tl_interp = nullptr;
    julie_free(interp);
}

YED_Thread_Lock::YED_Thread_Lock() : owned(false) {}

YED_Thread_Lock::YED_Thread_Lock(std::unique_lock<std::mutex> &&lock) : lock(std::move(lock)), owned(true) {}

YED_Thread_Lock::~YED_Thread_Lock() {
    if (!owned) { return; }
    julie->set_yed_context_owner(std::thread::id{});
    julie->n_queued_for_sync -= 1;
    bool notify = (julie->n_queued_for_sync == 0);
    this->lock.unlock();
    if (notify) {
        julie->yed_sync_cond.notify_all();
    }
}

void Julie::request_pump() {
    if (!this->pump_requested) {
        yed_force_update();
    }
    this->pump_requested = true;
}

YED_Thread_Lock Julie::pause_yed_thread_scoped() {
    if (this->yed_context_owner.load() == std::this_thread::get_id()) {
        return YED_Thread_Lock();
    }

    std::unique_lock lock(this->yed_sync_mtx);
    this->n_queued_for_sync += 1;
    if (tl_interp == nullptr) {
        this->request_pump();
    }
    while (!this->yed_thread_free) {
        this->yed_sync_cond.wait(lock);
    }
    this->yed_context_owner.store(std::this_thread::get_id());

    return YED_Thread_Lock(std::move(lock));
}

Julie_Value *Julie::get_event_object(Julie_Interp *interp) {
    Julie_Value *object = julie_object_value(interp);

    switch (this->current_event.kind) {
        case EVENT_KEY_PRESSED: {
            Julie_Value *sym = julie_symbol_value(interp, julie_get_string_id(interp, "'key"));
            char *key_str = IS_MOUSE(this->current_event.key) ? strdup("mouse") : yed_keys_to_string(1, &this->current_event.key);
            if (key_str == NULL) { key_str = strdup(""); }
            julie_object_insert_field(interp, object, sym, julie_string_value_giveaway(interp, key_str), NULL);
            break;
        }

        case EVENT_FRAME_ACTIVATED:
        case EVENT_FRAME_PRE_DELETE: {
            Julie_Value *sym = julie_symbol_value(interp, julie_get_string_id(interp, "'frame"));
            julie_object_insert_field(interp, object, sym, julie_sint_value(interp, this->current_event.frame_idx), NULL);
            break;
        }

        case EVENT_BUFFER_FOCUSED: {
            Julie_Value *sym_frame = julie_symbol_value(interp, julie_get_string_id(interp, "'frame"));
            julie_object_insert_field(interp, object, sym_frame, julie_sint_value(interp, this->current_event.frame_idx), NULL);
            Julie_Value *sym_buf = julie_symbol_value(interp, julie_get_string_id(interp, "'buffer"));
            julie_object_insert_field(interp, object, sym_buf,
                julie_string_value(interp, this->current_event.buffer_name.c_str()), NULL);
            break;
        }

        case EVENT_BUFFER_PRE_FOCUS: {
            Julie_Value *sym_frame = julie_symbol_value(interp, julie_get_string_id(interp, "'frame"));
            julie_object_insert_field(interp, object, sym_frame, julie_sint_value(interp, this->current_event.frame_idx), NULL);
            Julie_Value *sym_buf = julie_symbol_value(interp, julie_get_string_id(interp, "'buffer"));
            julie_object_insert_field(interp, object, sym_buf,
                julie_string_value(interp, this->current_event.buffer_name.c_str()), NULL);
            break;
        }

        case EVENT_BUFFER_POST_LOAD: {
            Julie_Value *sym_buf = julie_symbol_value(interp, julie_get_string_id(interp, "'buffer"));
            julie_object_insert_field(interp, object, sym_buf,
                julie_string_value(interp, this->current_event.buffer_name.c_str()), NULL);
            Julie_Value *sym_path = julie_symbol_value(interp, julie_get_string_id(interp, "'path"));
            julie_object_insert_field(interp, object, sym_path,
                this->current_event.path.empty()
                    ? julie_nil_value(interp)
                    : julie_string_value(interp, this->current_event.path.c_str()),
                NULL);
            break;
        }

        case EVENT_CURSOR_POST_MOVE: {
            Julie_Value *sym_frame = julie_symbol_value(interp, julie_get_string_id(interp, "'frame"));
            julie_object_insert_field(interp, object, sym_frame, julie_sint_value(interp, this->current_event.frame_idx), NULL);
            Julie_Value *sym_row = julie_symbol_value(interp, julie_get_string_id(interp, "'row"));
            julie_object_insert_field(interp, object, sym_row, julie_sint_value(interp, this->current_event.row), NULL);
            Julie_Value *sym_col = julie_symbol_value(interp, julie_get_string_id(interp, "'col"));
            julie_object_insert_field(interp, object, sym_col, julie_sint_value(interp, this->current_event.col), NULL);
            break;
        }

        case EVENT_PRE_DRAW_EVERYTHING: {
            break;
        }
    }

    return object;
}

struct Eval_Synchronizer {
    Eval_Synchronizer() {
        std::unique_lock sync_lock(julie->yed_sync_mtx);
        julie->yed_thread_free = true;
        sync_lock.unlock();
        julie->yed_sync_cond.notify_all();
    }
    ~Eval_Synchronizer() {
        std::unique_lock eval_lock(julie->eval_mtx);
        while (julie->n_pending_eval > 0) {
            julie->eval_cond.wait(eval_lock);
        }
        std::unique_lock sync_lock(julie->yed_sync_mtx);
        julie->yed_thread_free = false;
    }
};

void Error_Popup::kill_dds() {
    for (auto *dd : dds) { yed_kill_direct_draw(dd); }
    dds.clear();
}

static void popup_mouse_handler(yed_event *event);

void Error_Popup::dismiss() {
    if (mouse_handler_active) {
        yed_event_handler h;
        h.kind = EVENT_KEY_PRESSED;
        h.fn   = popup_mouse_handler;
        yed_delete_event_handler(h);
        yed_plugin_request_no_mouse_reporting(Self);
        mouse_handler_active = false;
    }
    kill_dds();
    click_regions.clear();
    active = false;
}

void Error_Popup::show(const char *f, int l, int c, const char *msg) {
    kill_dds();
    click_regions.clear();
    file    = f ? f : "";
    line    = l;
    col     = c;
    message = msg ? msg : "";
    if (!mouse_handler_active) {
        yed_event_handler h;
        h.kind = EVENT_KEY_PRESSED;
        h.fn   = popup_mouse_handler;
        yed_plugin_add_event_handler(Self, h);
        yed_plugin_request_mouse_reporting(Self);
        mouse_handler_active = true;
    }
    active = true;
    draw();
}

void Error_Popup::draw() {
    if (!active) { return; }
    kill_dds();
    click_regions.clear();

    yed_attrs attrs = yed_parse_attrs("&popup");
    if (ATTRS_EQ(attrs, ZERO_ATTR)) { attrs = yed_parse_attrs("&associate"); }
    if (ATTRS_EQ(attrs, ZERO_ATTR)) { attrs = yed_parse_attrs("&active");    }

    static const int   MAX_W  = 52;
    static const char *TITLE  = " Julie Error ";
    static const char *CMDS[] = {
        "julie-jump-to-error",
        "julie-view-output",
        "julie-dismiss-error",
    };
    static const int   N_CMDS   = 3;
    static const char *CMD_HDR  = "available commands:";

    /* word-wrap message at MAX_W */
    std::vector<std::string> msg_lines;
    {
        std::string rem = message;
        while (!rem.empty() && rem.back() == '\n') { rem.pop_back(); }
        if (rem.empty()) {
            msg_lines.push_back("");
        } else {
            while (!rem.empty()) {
                size_t nl   = rem.find('\n');
                std::string para = (nl == std::string::npos) ? rem : rem.substr(0, nl);
                rem = (nl == std::string::npos) ? "" : rem.substr(nl + 1);
                while ((int)para.size() > MAX_W) {
                    size_t brk = MAX_W;
                    size_t sp  = para.rfind(' ', MAX_W - 1);
                    if (sp != std::string::npos && sp > 0) { brk = sp; }
                    msg_lines.push_back(para.substr(0, brk));
                    size_t skip = brk;
                    while (skip < para.size() && para[skip] == ' ') { skip++; }
                    para = para.substr(skip);
                }
                msg_lines.push_back(para);
            }
        }
    }

    /* compute inner content width */
    int inner_w = (int)strlen(TITLE) + 2;
    for (auto &ln : msg_lines) {
        inner_w = std::max(inner_w, (int)ln.size() + 2);
    }
    inner_w = std::max(inner_w, (int)strlen(CMD_HDR) + 2);
    for (int i = 0; i < N_CMDS; i++) {
        inner_w = std::max(inner_w, (int)strlen(CMDS[i]) + 4);
    }

    auto repeat_str = [](const char *s, int n) -> std::string {
        std::string r;
        for (int i = 0; i < n; i++) { r += s; }
        return r;
    };
    auto pad_line = [&](const std::string &s) -> std::string {
        int spaces = inner_w - (int)s.size() - 1;
        if (spaces < 0) { spaces = 0; }
        return " " + s + std::string(spaces, ' ');
    };

    /* total rows: top + msgs + sep + cmd_hdr + N_CMDS + bot */
    int total_rows = 1 + (int)msg_lines.size() + 1 + 1 + N_CMDS + 1;
    int start_r    = ys->term_rows - total_rows - 2;
    int start_c    = ys->term_cols - inner_w - 1;

    popup_start_c = start_c;
    popup_end_c   = start_c + inner_w + 1;

    int r = start_r;

    std::string top = "┌" + std::string(TITLE) + repeat_str("─", inner_w - (int)strlen(TITLE)) + "┐";
    dds.push_back(yed_direct_draw(r++, start_c, attrs, top.c_str()));

    for (auto &ln : msg_lines) {
        std::string row_str = "│" + pad_line(ln) + "│";
        dds.push_back(yed_direct_draw(r++, start_c, attrs, row_str.c_str()));
    }

    std::string sep = "├" + repeat_str("─", inner_w) + "┤";
    dds.push_back(yed_direct_draw(r++, start_c, attrs, sep.c_str()));

    std::string hdr_row = "│" + pad_line(CMD_HDR) + "│";
    dds.push_back(yed_direct_draw(r++, start_c, attrs, hdr_row.c_str()));

    for (int i = 0; i < N_CMDS; i++) {
        std::string cmd_row = "│" + pad_line(std::string("  ") + CMDS[i]) + "│";
        dds.push_back(yed_direct_draw(r, start_c, attrs, cmd_row.c_str()));
        click_regions.push_back({ r, CMDS[i] });
        r++;
    }

    std::string bot = "└" + repeat_str("─", inner_w) + "┘";
    dds.push_back(yed_direct_draw(r, start_c, attrs, bot.c_str()));
}

Error_Location Error_Popup::get_location() {
    return { this->file, this->line, this->col };
}

Julie::Julie() {
}

void Julie::init() {
    this->interp_thread = std::thread(interp_thread_main);
}

Julie::~Julie() {
    teardown = true;
    this->yed_thread_relinquish();
    this->interp_messages.push({ .type = INTERP_MESSAGE_STOP });
    this->interp_thread.join();
}

void Julie::yed_thread_relinquish() {
    /* Check if another thread wants us to stop here so that it can do "yed stuff" */

    if (this->n_queued_for_sync == 0) { return; }

    std::unique_lock lock(this->yed_sync_mtx);

    if (this->n_queued_for_sync > 0) {
        this->yed_thread_free = true;
        this->yed_sync_cond.notify_all();

        while (this->n_queued_for_sync > 0) {
            this->yed_sync_cond.wait(lock);
        }

        this->yed_thread_free = false;
    }
}

void Julie::handle_yed_thread() {
    while (auto msg = this->editor_messages.try_pop()) {
        switch (msg->type) {
            case EDITOR_MESSAGE_JULIE_OUTPUT: {
                auto output_buff = yed_get_or_create_special_rdonly_buffer("*julie-output");

                u64 r = yed_buff_n_lines(output_buff);
                if (r == 0) { r = 1; }

                yed_line *last_line = yed_buff_get_line(output_buff, r);
                int c = last_line->visual_width + 1;

                output_buff->flags &= ~BUFF_RD_ONLY;
                output_buff->flags |= BUFF_NO_MOD_EVENTS;
                yed_buff_insert_string_no_undo(output_buff, msg->output.str, r, c);
                output_buff->flags &= ~BUFF_NO_MOD_EVENTS;
                output_buff->flags |= BUFF_RD_ONLY;

                {
                    yed_frame **fit;
                    array_traverse(ys->frames, fit) {
                        if (*fit != ys->active_frame && (*fit)->buffer == output_buff) {
                            yed_set_cursor_far_within_frame(*fit, yed_buff_n_lines(output_buff), 1);
                        }
                    }
                }

                free(msg->output.str);
                break;
            }

            case EDITOR_MESSAGE_JULIE_ERROR: {
                yed_cerr("Julie error%s%s — see *julie-output",
                            msg->error.file ? " in " : "",
                            msg->error.file ? msg->error.file : "");
                this->error_popup.show(msg->error.file,
                                        msg->error.line,
                                        msg->error.col,
                                        msg->error.message);
                free(msg->error.file);
                free(msg->error.message);
                break;
            }
        }
    }
    this->pump_requested = false;
    if (this->n_queued_for_sync > 0) {
        yed_force_update();
    }
}

void Julie::setup_current_event(yed_event *event) {
    this->current_event = {};
    this->current_event.kind = event->kind;

    switch (event->kind) {
        case EVENT_KEY_PRESSED:
            this->current_event.key = event->key;
            break;

        case EVENT_FRAME_ACTIVATED:
        case EVENT_FRAME_PRE_DELETE: {
            if (event->frame != NULL) {
                int i = 0;
                yed_frame **fit;
                array_traverse(ys->frames, fit) {
                    if (*fit == event->frame) {
                        this->current_event.frame_idx = i;
                        break;
                    }
                    i += 1;
                }
            }
            break;
        }

        case EVENT_BUFFER_POST_LOAD:
            if (event->buffer != NULL) {
                this->current_event.buffer_name = event->buffer->name;
            }
            if (event->path != NULL) {
                this->current_event.path = event->path;
            }
            break;

        case EVENT_BUFFER_PRE_FOCUS:
        case EVENT_BUFFER_FOCUSED:
            if (event->frame != NULL) {
                int i = 0;
                yed_frame **fit;
                array_traverse(ys->frames, fit) {
                    if (*fit == event->frame) {
                        this->current_event.frame_idx = i;
                        break;
                    }
                    i += 1;
                }
            }
            if (event->buffer != NULL) {
                this->current_event.buffer_name = event->buffer->name;
            }
            break;

        case EVENT_CURSOR_POST_MOVE:
            if (event->frame != NULL) {
                int i = 0;
                yed_frame **fit;
                array_traverse(ys->frames, fit) {
                    if (*fit == event->frame) {
                        this->current_event.frame_idx = i;
                        break;
                    }
                    i += 1;
                }
            }
            this->current_event.row = event->new_row;
            this->current_event.col = event->new_col;
            break;

        case EVENT_PRE_DRAW_EVERYTHING:
            break;

        default:
            break;
    }
}

void Julie::set_cmd_dispatch_name(const char *name) {
    this->cmd_dispatch_name = name;
}

const std::string& Julie::get_cmd_dispatch_name() {
    return this->cmd_dispatch_name;
}

void Julie::push_interp_message(Interp_Message msg) {
    {
        std::unique_lock lock(this->eval_mtx);
        this->n_pending_eval += 1;
    }
    this->interp_messages.push(std::move(msg));
}

void Julie::eval_string(const char *code_string) {
    if (tl_interp != nullptr) {
        direct_eval_string(tl_interp, code_string);
        return;
    }
    {
        Eval_Synchronizer sync;
        this->push_interp_message({ .type = INTERP_MESSAGE_EVAL, .eval = { .code = strdup(code_string) } });
    }
    this->handle_yed_thread();
}

void Julie::run_on_event(yed_event *event) {
    if (tl_interp != nullptr) {
        Current_Event_Data saved = this->current_event;
        this->setup_current_event(event);
        direct_eval_event(tl_interp, event->kind);
        this->current_event = saved;
        return;
    }
    this->setup_current_event(event);
    {
        Eval_Synchronizer sync;
        this->push_interp_message({ .type = INTERP_MESSAGE_EVENT, .event = { .kind = event->kind } });
    }
    this->handle_yed_thread();
}




static void prompt_start(int n_args, char **args) {
    int   i;
    char *lazy_space;

    ys->interactive_command = "julie-prompt";
    ys->cmd_prompt = "JULIE> ";
    yed_clear_cmd_buff();

    lazy_space = "";
    for (i = 0; i < n_args; i += 1) {
        yed_append_text_to_cmd_buff(lazy_space);
        yed_append_text_to_cmd_buff(args[i]);
        lazy_space = " ";
    }

    yed_cmd_line_readline_reset(&prompt_readline, &prompt_hist);
}

static void prompt_cancel(void) {
    ys->interactive_command = NULL;
    yed_clear_cmd_buff();
/*     prompt_compl_cleanup(); */
}

static void prompt_run(void) {
    char  *string;
    char **mru;

    ys->interactive_command = NULL;

    string = yed_cmd_line_readline_get_string();

    yed_clear_cmd_buff();

    if (strlen(string) > 0) {
        julie->eval_string(string);
    }

    mru = (char**)array_last(prompt_hist);

    if (strlen(string)
    &&  mru
    &&  strcmp(*mru, string) == 0) {
        free(string);
    } else {
        array_push(prompt_hist, string);
    }

/*     prompt_compl_cleanup(); */
}

void prompt_take_key(int key) {
    switch (key) {
        case ENTER:
            prompt_run();
            break;
        case CTRL_C:
        case ESC:
            prompt_cancel();
            break;
#if 0
        case TAB:
            prompt_do_compl_fwd();
            break;
        case SHIFT_TAB:
            prompt_do_compl_bwd();
            break;
#endif
        default:
/*             prompt_compl_cleanup(); */
            yed_cmd_line_readline_take_key(&prompt_readline, key);
    }
}

static void cmd_prompt(int n_args, char **args) {
    int key;

    if (!ys->interactive_command) {
        prompt_start(n_args, args);
    } else {
        sscanf(args[0], "%d", &key);
        prompt_take_key(key);
    }
}

bool Julie::error_popup_active() {
    return this->error_popup.active;
}

void Julie::dismiss_error_popup() {
    this->error_popup.dismiss();
}

Error_Location Julie::get_error_location() {
    return this->error_popup.get_location();
}

static void cmd_dismiss_error(int n_args, char **args) {
    if (n_args != 0) {
        yed_cerr("expected 0 arguments, but got %d", n_args);
        return;
    }
    julie->dismiss_error_popup();
}

static void cmd_jump_to_error(int n_args, char **args) {
    if (n_args != 0) {
        yed_cerr("expected 0 arguments, but got %d", n_args);
        return;
    }
    if (!julie->error_popup_active()) {
        yed_cerr("no active Julie error");
        return;
    }

    auto loc = julie->get_error_location();
    if (loc.file.empty()) {
        yed_cerr("Julie error has no location info — see *julie-output");
        return;
    }
    int line = loc.line;
    int col  = loc.col;
    YEXE("buffer", (char *)loc.file.c_str());
    if (ys->active_frame) {
        yed_set_cursor_far_within_frame(ys->active_frame, line, col > 0 ? col : 1);
    }
}

static void cmd_view_output(int n_args, char **args) {
    if (n_args != 0) {
        yed_cerr("expected 0 arguments, but got %d", n_args);
        return;
    }
    YEXE("special-buffer-prepare-focus", "*julie-output");
    YEXE("buffer", "*julie-output");
}

static void cmd_eval_buffer(int n_args, char **args) {
    yed_buffer *buff;
    char       *text;

    if (n_args != 0) {
        yed_cerr("expected 0 arguments, but got %d", n_args);
        return;
    }
    if (!ys->active_frame || !ys->active_frame->buffer) {
        yed_cerr("no active buffer");
        return;
    }
    buff = ys->active_frame->buffer;
    text = yed_get_buffer_text(buff);
    if (!text) {
        yed_cerr("could not get buffer text");
        return;
    }
    julie->eval_string(text);
    free(text);
}

static void cmd_eval(int n_args, char **args) {
    if (n_args != 1) {
        yed_cerr("expected 1 argument, but got %d", n_args);
        return;
    }

    julie->eval_string(args[0]);
}

static void unload(yed_plugin *self) {
    (void)self;
}

static void pump(yed_event *event) {
    julie->yed_thread_relinquish();
    julie->handle_yed_thread();
}

static void key(yed_event *event) {
    julie->run_on_event(event);
}

bool Julie::error_popup_handle_click(int r, int c) {
    auto &ep = this->error_popup;

    if (c < ep.popup_start_c || c > ep.popup_end_c) { return false; }

    for (auto &cr : ep.click_regions) {
        if (r == cr.row) {
            YEXE((char *)cr.command.c_str());
            return true;
        }
    }

    return false;
}

static void popup_mouse_handler(yed_event *event) {
    if (!IS_MOUSE(event->key))                             { return; }
    if (MOUSE_KIND(event->key)   != MOUSE_PRESS)           { return; }
    if (MOUSE_BUTTON(event->key) != MOUSE_BUTTON_LEFT)     { return; }

    if (julie->error_popup_handle_click(MOUSE_ROW(event->key), MOUSE_COL(event->key))) {
        event->cancel = 1;
    }
}

static void frame_activated(yed_event *event) {
    julie->run_on_event(event);
}

static void buffer_load(yed_event *event) {
    julie->run_on_event(event);
}

static void buffer_focused(yed_event *event) {
    julie->run_on_event(event);
}

static void buffer_pre_focused(yed_event *event) {
    julie->run_on_event(event);
}

static void frame_pre_delete(yed_event *event) {
    julie->run_on_event(event);
}

static void cursor_move(yed_event *event) {
    julie->run_on_event(event);
}

static void buffmod(yed_event *event) {
    yed_buffer *buff = yed_get_or_create_special_rdonly_buffer("*julie-output");

    if (event->buffer != buff) { return; }

    yed_frame **fit;
    array_traverse(ys->frames, fit) {
        if ((*fit) != ys->active_frame
        &&  (*fit)->buffer == buff) {
            yed_set_cursor_far_within_frame((*fit), yed_buff_n_lines(buff), 1);
        }
    }

}

void Julie::cmd_dispatch(int n_args, char **args) {
    std::string cmd = julie->get_cmd_dispatch_name();

    if (tl_interp != nullptr) {
        direct_eval_cmd(tl_interp, cmd.c_str(), n_args, args);
        return;
    }

    char  *cmd_cpy  = strdup(cmd.c_str());
    char **args_cpy = (char**)malloc(n_args * sizeof(*args));

    for (int i = 0; i < n_args; i += 1) {
        args_cpy[i] = strdup(args[i]);
    }

    {
        Eval_Synchronizer sync;
        julie->push_interp_message({ .type = INTERP_MESSAGE_CMD, .cmd = { .cmd = cmd_cpy, .n_args = n_args, .args = args_cpy } });
    }

    julie->handle_yed_thread();
}

static void cmdrun(yed_event *event) {
    yed_command cmd = yed_get_command(event->cmd_name);
    if (cmd != Julie::cmd_dispatch) { return; }

    julie->set_cmd_dispatch_name(event->cmd_name);
}

static void draw(yed_event *event) {
    julie->run_on_event(event);
}

extern "C"
int yed_plugin_boot(yed_plugin *self) {
    yed_event_handler h;

    YED_PLUG_VERSION_CHECK();

    Self = self;

    yed_plugin_set_unload_fn(self, unload);

    yed_get_or_create_special_rdonly_buffer("*julie-output");

    prompt_hist = array_make(char*);
    yed_cmd_line_readline_make(&prompt_readline, &prompt_hist);

    h.kind = EVENT_PRE_PUMP;
    h.fn   = pump;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_KEY_PRESSED;
    h.fn   = key;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_FRAME_ACTIVATED;
    h.fn   = frame_activated;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_BUFFER_POST_LOAD;
    h.fn   = buffer_load;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_BUFFER_FOCUSED;
    h.fn   = buffer_focused;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_BUFFER_PRE_FOCUS;
    h.fn   = buffer_pre_focused;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_FRAME_PRE_DELETE;
    h.fn   = frame_pre_delete;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_CURSOR_POST_MOVE;
    h.fn   = cursor_move;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_BUFFER_POST_MOD;
    h.fn   = buffmod;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_CMD_PRE_RUN;
    h.fn   = cmdrun;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_PRE_DRAW_EVERYTHING;
    h.fn   = draw;
    yed_plugin_add_event_handler(self, h);

    if (yed_get_var("julie-debug-log") == NULL) {
        yed_set_var("julie-debug-log", "yes");
    }

    yed_plugin_set_command(self, "julie-prompt",        cmd_prompt);
    yed_plugin_set_command(self, "julie-eval",          cmd_eval);
    yed_plugin_set_command(self, "julie-dismiss-error", cmd_dismiss_error);
    yed_plugin_set_command(self, "julie-jump-to-error", cmd_jump_to_error);
    yed_plugin_set_command(self, "julie-view-output",   cmd_view_output);
    yed_plugin_set_command(self, "julie-eval-buffer",   cmd_eval_buffer);

    julie = &_julie;
    julie->init();

    return 0;
}

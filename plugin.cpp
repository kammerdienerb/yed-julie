#include <memory>
#include <vector>
#include <deque>
#include <list>
#include <map>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <unordered_map>
#include <unordered_set>

extern "C" {
#include "julie.h"
#include <yed/plugin.h>
}


#define DBG_LOG_ON

#define LOG__XSTR(x) #x
#define LOG_XSTR(x) LOG__XSTR(x)

#define LOG(...)                                                   \
do {                                                               \
    LOG_FN_ENTER();                                                \
    yed_log(__VA_ARGS__);                                          \
    LOG_EXIT();                                                    \
} while (0)

#define ELOG(...)                                                  \
do {                                                               \
    LOG_FN_ENTER();                                                \
    yed_log("[!] " __VA_ARGS__);                                   \
    LOG_EXIT();                                                    \
} while (0)

#ifdef DBG_LOG_ON
#define DBG(...)                                                   \
do {                                                               \
    if (yed_var_is_truthy("julie-debug-log")) {                    \
        LOG_FN_ENTER();                                            \
        yed_log(__FILE__ ":" LOG_XSTR(__LINE__) ": " __VA_ARGS__); \
        LOG_EXIT();                                                \
    }                                                              \
} while (0)
#else
#define DBG(...) ;
#endif



template <typename T>
struct Message_Queue {
    std::mutex              mtx;
    std::condition_variable cond;
    std::deque<T>           items;

    void push(const T &elem) {
        std::unique_lock lock(this->mtx);
        this->items.push_back(elem);
        lock.unlock();
        this->cond.notify_one();
    }

    std::optional<T> try_pop() {
        std::unique_lock lock(this->mtx);
        if (this->items.empty()) {
            return {};
        }
        auto elem = this->items.front();
        this->items.pop_front();
        return elem;
    }

    T pop() {
        std::unique_lock lock(this->mtx);
        while (this->items.empty()) {
            this->cond.wait(lock);
        }
        auto elem = this->items.front();
        this->items.pop_front();
        return elem;
    }
};


enum {
    EDITOR_MESSAGE_JULIE_OUTPUT,
};

struct Editor_Message_Output {
    char *str;
};

struct Editor_Message {
    int type;
    union {
        Editor_Message_Output output;
    };
};


struct Interp_Thread_Data {
    bool            initialized     = false;
    Julie_String_ID sid_config_path = nullptr;
    Julie_String_ID sid_CONFIG_PATH = nullptr;
    Julie_String_ID sid_CURSOR_WORD = nullptr;
    Julie_String_ID sid_LINE        = nullptr;
    Julie_String_ID sid_LINENO      = nullptr;
    Julie_String_ID sid_COLNO       = nullptr;
    Julie_String_ID sid_EVENT       = nullptr;
};

thread_local Interp_Thread_Data interp_thread_data;

struct Current_Event_Data {
    int key;
};

class Julie {
    std::thread::id                main_thread_id;
    Julie_Interp                  *main_interp;
    Message_Queue<Editor_Message>  editor_messages;
    bool                           yed_thread_free = false;
    int                            n_queued_for_sync = 0;
    std::mutex                     yed_sync_mtx;
    std::condition_variable        yed_sync_cond;
    Current_Event_Data             current_event;

    Julie() {
        this->main_thread_id = std::this_thread::get_id();

        this->main_interp = julie_init_interp();

        julie_set_error_callback(this->main_interp,  interp_error_cb);
        julie_set_output_callback(this->main_interp, interp_output_cb);
        julie_set_eval_callback(this->main_interp,   interp_pre_eval_cb);

        Julie_Value *list = julie_list_value(this->main_interp);
        julie_bind(this->main_interp, julie_get_string_id(this->main_interp, "@on-key"), &list);
    }

    ~Julie() {
        julie_free(this->main_interp);
    }

    struct YED_Thread_Lock {
        std::unique_lock<std::mutex> lock;

        YED_Thread_Lock() {}
        YED_Thread_Lock(std::unique_lock<std::mutex> &&lock) : lock(std::move(lock)) {}

        ~YED_Thread_Lock() {
            if (std::this_thread::get_id() != Julie::get().main_thread_id) {
                Julie::get().n_queued_for_sync -= 1;
                bool notify = (Julie::get().n_queued_for_sync == 0);
                this->lock.unlock();
                if (notify) {
                    Julie::get().yed_sync_cond.notify_all();
                }
            }
        }
    };

    YED_Thread_Lock pause_yed_thread_scoped() {
        if (std::this_thread::get_id() == Julie::get().main_thread_id) { return {}; }

        std::unique_lock lock(this->yed_sync_mtx);
        this->n_queued_for_sync += 1;
        if (this->n_queued_for_sync == 1) {
            yed_force_update();
        }
        while (!this->yed_thread_free) {
            this->yed_sync_cond.wait(lock);
        }

        return YED_Thread_Lock(std::move(lock));
    }

    static void _init_thread_data(Julie_Interp *interp) {
        interp_thread_data.sid_config_path = julie_get_string_id(interp, get_config_path());
        interp_thread_data.sid_CONFIG_PATH = julie_get_string_id(interp, "$CONFIG-PATH");
        interp_thread_data.sid_CURSOR_WORD = julie_get_string_id(interp, "$CURSOR-WORD");
        interp_thread_data.sid_LINE        = julie_get_string_id(interp, "$LINE");
        interp_thread_data.sid_LINENO      = julie_get_string_id(interp, "$LINENO");
        interp_thread_data.sid_COLNO       = julie_get_string_id(interp, "$COLNO");
        interp_thread_data.sid_EVENT       = julie_get_string_id(interp, "$EVENT");
    }

    static void init_thread_data(Julie_Interp *interp) {
        if (interp_thread_data.initialized) { return; }

        if (interp == Julie::get().main_interp) {
            /* Don't pause interp running on main thread. */
            _init_thread_data(interp);
        } else {
            auto lock = Julie::get().pause_yed_thread_scoped();
            _init_thread_data(interp);
        }

    }

    Julie_Value *get_event_object(Julie_Interp *interp) {
        Julie_Value *object = julie_object_value(interp);

        Julie_Value *sym_value = julie_symbol_value(interp, julie_get_string_id(interp, "'key"));

        char *key_str = yed_keys_to_string(1, &this->current_event.key);
        if (key_str == NULL) { key_str = strdup(""); }

        Julie_Value *str_value = julie_string_value_giveaway(interp, key_str);

        julie_object_insert_field(interp, object, sym_value, str_value, NULL);

        return object;
    }

    static Message_Queue<Editor_Message> &get_editor_messages() {
        return Julie::get().editor_messages;
    }

    static void interp_error_cb(Julie_Error_Info *info) {
        char                  *s;
        char                   buff[1024];
        unsigned               i;
        Julie_Backtrace_Entry *it;

        s = julie_get_pretty_error_string(info, "", "", "");
        interp_output_cb(s, strlen(s));
        free(s);

    /*     set_err(info->file_id != NULL, */
    /*             info->file_id != NULL ? julie_get_cstring(info->file_id) : NULL, */
    /*             info->line, */
    /*             info->col, */
    /*             err_buff); */

        snprintf(buff, sizeof(buff), "\n");
        interp_output_cb(buff, strlen(buff));

        i = 1;
        while ((it = julie_bt_entry(info->interp, i)) != NULL) {
            s = julie_to_string(info->interp, it->fn, 0);
            snprintf(buff, sizeof(buff), "    %s:%llu:%llu %s\n",
                    it->file_id == NULL ? "<?>" : julie_get_cstring(it->file_id),
                    it->line,
                    it->col,
                    s);
            free(s);
            interp_output_cb(buff, strlen(buff));

            i += 1;
        }

        julie_free_error_info(info);
    }

    static void interp_output_cb(const char *s, int n_bytes) {
        Editor_Message msg;

        msg.type = EDITOR_MESSAGE_JULIE_OUTPUT;
        msg.output.str = (char*)malloc(n_bytes + 1);
        memcpy(msg.output.str, s, n_bytes);
        msg.output.str[n_bytes] = 0;

        Julie::get_editor_messages().push(msg);
        yed_force_update();
    }

    static Julie_Status interp_eval_custom_symbol(Julie_Interp *interp, Julie_Value *value, Julie_Value **result) {
        Julie_String_ID id = julie_value_string_id(interp, value);

        Julie::get().init_thread_data(interp);

        if (id == interp_thread_data.sid_CONFIG_PATH) {
            *result = julie_interned_string_value(interp, interp_thread_data.sid_config_path);
        } else if (id == interp_thread_data.sid_CURSOR_WORD) {
            auto lock = Julie::get().pause_yed_thread_scoped();
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
            auto lock = Julie::get().pause_yed_thread_scoped();

            if (ys->active_frame != NULL) {
                *result = julie_sint_value(interp, ys->active_frame->cursor_line);
            } else {
                *result = julie_sint_value(interp, 0);
            }
        } else if (id == interp_thread_data.sid_COLNO) {
            auto lock = Julie::get().pause_yed_thread_scoped();

            if (ys->active_frame != NULL) {
                *result = julie_sint_value(interp, ys->active_frame->cursor_col);
            } else {
                *result = julie_sint_value(interp, 0);
            }
        } else if (id == interp_thread_data.sid_EVENT) {
            auto lock = Julie::get().pause_yed_thread_scoped();
            *result = Julie::get().get_event_object(interp);
        }

        return JULIE_SUCCESS;
    }

    static Julie_Status interp_pre_eval_cb(Julie_Interp *interp, Julie_Value *value, Julie_Value **result) {
        if (value->type == JULIE_SYMBOL) {
            return interp_eval_custom_symbol(interp, value, result);
        }

        return JULIE_SUCCESS;
    }

public:
    static Julie &get() {
        static Julie julie;
        return julie;
    }

    void eval_string(const char *code_string) {
        Julie_Value *parse = julie_symbol_value(this->main_interp, julie_get_string_id(this->main_interp, "parse-julie"));
        Julie_Value *code  = julie_string_value(this->main_interp, code_string);
        Julie_Value *list  = julie_list_value(this->main_interp);
        JULIE_ARRAY_PUSH(list->list, parse);
        JULIE_ARRAY_PUSH(list->list, code);
        Julie_Value *apply = julie_list_value(this->main_interp);
        JULIE_ARRAY_PUSH(apply->list, list);

        Julie_Value *result;
        Julie_Status status = julie_eval(this->main_interp, apply, &result);
        if (status == JULIE_SUCCESS) {
            julie_free_value(this->main_interp, result);
        }
    }

    void yed_thread_relinquish() {
        bool paused = false;

        /* Check if another thread wants us to stop here so that it can do "yed stuff" */
        std::unique_lock lock(this->yed_sync_mtx);

        if (this->n_queued_for_sync > 0) {
            this->yed_thread_free = true;
            this->yed_sync_cond.notify_all();
            paused = true;
        }

        if (paused) {
            while (this->n_queued_for_sync > 0) {
                this->yed_sync_cond.wait(lock);
            }
            this->yed_thread_free = false;
        }
    }

    void handle_yed_thread() {
        while (auto msg = this->editor_messages.try_pop()) {
            switch (msg->type) {
                case EDITOR_MESSAGE_JULIE_OUTPUT: {
                    auto output_buff = yed_get_or_create_special_rdonly_buffer("*julie-output");

                    u64 r = yed_buff_n_lines(output_buff);
                    if (r == 0) { r = 1; }

                    yed_line *last_line = yed_buff_get_line(output_buff, r);
                    int c = last_line->visual_width + 1;

                    output_buff->flags &= ~BUFF_RD_ONLY;
                    yed_buff_insert_string_no_undo(output_buff, msg->output.str, r, c);
                    output_buff->flags |= BUFF_RD_ONLY;

                    free(msg->output.str);
                    break;
                }
            }
        }
    }

    void setup_current_event(yed_event *event) {
        memset(&this->current_event, 0, sizeof(this->current_event));

        switch (event->kind) {
            case EVENT_KEY_PRESSED:
                this->current_event.key = event->key;
                break;

            default:
                break;
        }
    }

    void run_on_key(yed_event *event) {
        this->setup_current_event(event);

        Julie_Value *lookup = julie_lookup(this->main_interp, julie_get_string_id(this->main_interp, "@on-key"));
        if (lookup == NULL || lookup->type != JULIE_LIST) { return; }

        Julie_Value *it;
        ARRAY_FOR_EACH(lookup->list, it) {
            Julie_Value *result = NULL;
            julie_eval(this->main_interp, it, &result);
            if (result != NULL) {
                julie_free_value(this->main_interp, result);
            }
        }
    }
};





static array_t                prompt_hist;
static yed_cmd_line_readline  prompt_readline;

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
        Julie::get().eval_string(string);
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


static void cmd_eval(int n_args, char **args) {
    if (n_args != 1) {
        yed_cerr("expected 1 argument, but got %d", n_args);
        return;
    }

    Julie::get().eval_string(args[0]);
}

static void unload(yed_plugin *self) {
    (void)self;
}

static void pump(yed_event *event) {
    Julie::get().yed_thread_relinquish();
    Julie::get().handle_yed_thread();
}

static void key(yed_event *event) {
    Julie::get().run_on_key(event);
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

extern "C"
int yed_plugin_boot(yed_plugin *self) {
    yed_event_handler h;

    YED_PLUG_VERSION_CHECK();

    yed_plugin_set_unload_fn(self, unload);

    Julie::get();

    yed_get_or_create_special_rdonly_buffer("*julie-output");

    prompt_hist = array_make(char*);
    yed_cmd_line_readline_make(&prompt_readline, &prompt_hist);

    h.kind = EVENT_PRE_PUMP;
    h.fn   = pump;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_KEY_PRESSED;
    h.fn   = key;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_BUFFER_POST_MOD;
    h.fn   = buffmod;
    yed_plugin_add_event_handler(self, h);

    if (yed_get_var("julie-debug-log") == NULL) {
        yed_set_var("julie-debug-log", "yes");
    }

    yed_plugin_set_command(self, "julie-prompt", cmd_prompt);
    yed_plugin_set_command(self, "julie-eval",   cmd_eval);

    return 0;
}

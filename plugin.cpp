#include <memory>
#include <vector>
#include <deque>
#include <list>
#include <map>
#include <string>
#include <thread>
#include <atomic>
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


static yed_frame *get_frame(int idx) {
    if (idx < 0 || idx >= (int)array_len(ys->frames)) { return NULL; }
    return *(yed_frame**)array_item(ys->frames, idx);
}


struct Julie;
Julie *julie;
yed_plugin *Self;


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

    void push(const T &&elem) {
        std::unique_lock lock(this->mtx);
        this->items.emplace_back(std::move(elem));
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
        auto elem = std::move(this->items.front());
        this->items.pop_front();
        return elem;
    }
};

enum {
    INTERP_MESSAGE_STOP,
    INTERP_MESSAGE_EVAL,
    INTERP_MESSAGE_CMD,
    INTERP_MESSAGE_EVENT,
};

struct Interp_Message_Stop {};

struct Interp_Message_Eval {
    char *code;
};

struct Interp_Message_Cmd {
    char  *cmd;
    int    n_args;
    char **args;
};

struct Interp_Message_Event {
    int kind;
};

struct Interp_Message {
    int type;
    union {
        Interp_Message_Stop  stop;
        Interp_Message_Eval  eval;
        Interp_Message_Cmd   cmd;
        Interp_Message_Event event;
    };

    void destroy() {
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
    Julie_String_ID sid_BUFFNAME    = nullptr;
    Julie_String_ID sid_LINE        = nullptr;
    Julie_String_ID sid_LINENO      = nullptr;
    Julie_String_ID sid_COLNO       = nullptr;
    Julie_String_ID sid_NUMFRAMES  = nullptr;
    Julie_String_ID sid_FRAME       = nullptr;
    Julie_String_ID sid_EVENT       = nullptr;
};

thread_local Interp_Thread_Data interp_thread_data;

struct Current_Event_Data {
    int key;
};

class Julie {
    std::thread                    interp_thread;
    Message_Queue<Interp_Message>  interp_messages;
    Message_Queue<Editor_Message>  editor_messages;
    std::atomic<bool>              pump_requested = false;
    bool                           yed_thread_free = false;
    std::atomic<int>               n_queued_for_sync = 0;
    std::mutex           yed_sync_mtx;
    std::condition_variable        yed_sync_cond;
    bool                           teardown = false;
    bool                           eval_running = false;
    std::mutex                     eval_mtx;
    std::condition_variable        eval_cond;
    Current_Event_Data             current_event;
    std::string                    cmd_dispatch_name;

    static void interp_thread_main() {
        Julie_Interp *interp = julie_init_interp();

        julie_set_error_callback(interp,  interp_error_cb);
        julie_set_output_callback(interp, interp_output_cb);
        julie_set_eval_callback(interp,   interp_pre_eval_cb);

        Julie_Value *list = julie_list_value(interp);
        julie_bind(interp, julie_get_string_id(interp, "@on-key"), &list);

        julie_bind_fn(interp, julie_get_string_id(interp, "@yexe"), _yexe);
        julie_bind_fn(interp, julie_get_string_id(interp, "@command"), _command);
        julie_bind_fn(interp, julie_get_string_id(interp, "@cprint"), _cprint);
        julie_bind_fn(interp, julie_get_string_id(interp, "@cerr"), _cerr);
        julie_bind_fn(interp, julie_get_string_id(interp, "@buff-nlines"), _buff_nlines);
        julie_bind_fn(interp, julie_get_string_id(interp, "@buff-line"), _buff_line);
        julie_bind_fn(interp, julie_get_string_id(interp, "@buff-lines"), _buff_lines);
        julie_bind_fn(interp, julie_get_string_id(interp, "@activate-frame"), _activate_frame);

        while (true) {
            Interp_Message msg = julie->interp_messages.pop();

            switch (msg.type) {
                case INTERP_MESSAGE_STOP: goto out;

                case INTERP_MESSAGE_EVAL: {
                    Julie_Array        *roots = JULIE_ARRAY_INIT;
                    unsigned long long  err_line;
                    unsigned long long  err_col;

                    Julie_Status status = julie_parse_roots(interp, &roots, msg.eval.code, strlen(msg.eval.code), &err_line, &err_col, 1);
                    if (status != JULIE_SUCCESS) {
                        julie_make_parse_error(interp, err_line, err_col, status);
                        break;
                    }

                    if (julie_array_len(roots) == 0) {
                        julie_array_free(roots);
                        break;
                    }


                    Julie_Value *code;
                    if (julie_array_len(roots) == 1) {
                        code = (Julie_Value*)julie_array_elem(roots, 0);
                    } else {
                        Julie_Value *do_list = julie_list_value(interp);
                        Julie_Value *do_sym  = julie_symbol_value(interp, julie_get_string_id(interp, "do"));
                        JULIE_ARRAY_PUSH(do_list->list, do_sym);
                        Julie_Value *it;
                        ARRAY_FOR_EACH(roots, it) {
                            JULIE_ARRAY_PUSH(do_list->list, it);
                        }
                        code = do_list;
                    }

                    Julie_Value *apply = julie_list_value(interp);
                    JULIE_ARRAY_PUSH(apply->list, code);

                    julie_array_free(roots);

                    Julie_Value *result;
                    status = julie_eval(interp, apply, &result);
                    if (status == JULIE_SUCCESS) {
                        julie_free_value(interp, result);
                    }

                    julie_free_value(interp, apply);

                    break;
                }

                case INTERP_MESSAGE_CMD: {
                    Julie_Value *lookup = julie_lookup(interp, julie_get_string_id(interp, msg.cmd.cmd));

                    if (lookup == NULL || lookup->type != JULIE_FN) {
                        break;
                    }

                    Julie_Value *list  = julie_list_value(interp);
                    JULIE_ARRAY_PUSH(list->list, julie_symbol_value(interp, julie_get_string_id(interp, msg.cmd.cmd)));
                    for (int i = 0; i < msg.cmd.n_args; i += 1) {
                        JULIE_ARRAY_PUSH(list->list, julie_string_value(interp, msg.cmd.args[i]));
                    }
                    Julie_Value *apply = julie_list_value(interp);
                    JULIE_ARRAY_PUSH(apply->list, list);

                    Julie_Value *result;
                    Julie_Status status = julie_eval(interp, apply, &result);
                    if (status == JULIE_SUCCESS) {
                        julie_free_value(interp, result);
                    }

                    julie_free_value(interp, apply);

                    break;
                }

                case INTERP_MESSAGE_EVENT: {
                    switch (msg.event.kind) {
                        case EVENT_KEY_PRESSED: {
                            Julie_Value *lookup = julie_lookup(interp, julie_get_string_id(interp, "@on-key"));
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
                            break;
                        }
                    }
                    break;
                }
            }

            msg.destroy();

            {
                std::unique_lock lock(julie->eval_mtx);
                julie->eval_running = false;
            }
            julie->eval_cond.notify_one();
        }

out:;
        julie_free(interp);
    }

    struct YED_Thread_Lock {
        std::unique_lock<std::mutex> lock;

        YED_Thread_Lock() {}
        YED_Thread_Lock(std::unique_lock<std::mutex> &&lock) : lock(std::move(lock)) {}

        ~YED_Thread_Lock() {
            julie->n_queued_for_sync -= 1;
            bool notify = (julie->n_queued_for_sync == 0);
            this->lock.unlock();
            if (notify) {
                julie->yed_sync_cond.notify_all();
            }
        }
    };

    void request_pump() {
        if (!this->pump_requested) {
            yed_force_update();
        }
        this->pump_requested = true;
    }

    YED_Thread_Lock pause_yed_thread_scoped() {
        std::unique_lock lock(this->yed_sync_mtx);
        this->n_queued_for_sync += 1;
        this->request_pump();
        while (!this->yed_thread_free) {
            this->yed_sync_cond.wait(lock);
        }

        return YED_Thread_Lock(std::move(lock));
    }

    static void init_thread_data(Julie_Interp *interp) {
        if (interp_thread_data.initialized) { return; }

        auto lock = julie->pause_yed_thread_scoped();

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
    }

    Julie_Value *get_event_object(Julie_Interp *interp) {
        Julie_Value *object = julie_object_value(interp);

        Julie_Value *sym_value = julie_symbol_value(interp, julie_get_string_id(interp, "'key"));

        char *key_str = IS_MOUSE(this->current_event.key) ? strdup("mouse") : yed_keys_to_string(1, &this->current_event.key);
        if (key_str == NULL) { key_str = strdup(""); }

        Julie_Value *str_value = julie_string_value_giveaway(interp, key_str);

        julie_object_insert_field(interp, object, sym_value, str_value, NULL);

        return object;
    }

    static Message_Queue<Editor_Message> &get_editor_messages() {
        return julie->editor_messages;
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

        julie_free_error_info(info);
    }

    static void interp_output_cb(const char *s, int n_bytes) {
        Editor_Message msg;

        msg.type = EDITOR_MESSAGE_JULIE_OUTPUT;
        msg.output.str = (char*)malloc(n_bytes + 1);
        memcpy(msg.output.str, s, n_bytes);
        msg.output.str[n_bytes] = 0;

        Julie::get_editor_messages().push(msg);
        julie->request_pump();
    }

    static Julie_Status interp_eval_custom_symbol(Julie_Interp *interp, Julie_Value *value, Julie_Value **result) {
        Julie_String_ID id = julie_value_string_id(interp, value);

        julie->init_thread_data(interp);

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

    static Julie_Status interp_pre_eval_cb(Julie_Interp *interp, Julie_Value *value, Julie_Value **result) {
        if (julie->teardown) { return JULIE_ERR_EVAL_CANCELLED; }

        if (value->type == JULIE_SYMBOL) {
            return interp_eval_custom_symbol(interp, value, result);
        }

        return JULIE_SUCCESS;
    }

    static Julie_Status _yexe(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
        Julie_Status status = JULIE_SUCCESS;

        std::vector<char*> strings;

        *result = NULL;

        if (n_values < 1) {
            status = JULIE_ERR_ARITY;
            julie_make_arity_error(interp, expr, 1, n_values, 1);
            goto out;
        }

        {
            Julie_Value *cmd = NULL;
            status = julie_eval(interp, values[0], &cmd);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out;
            }
            if (cmd->type != JULIE_STRING) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)cmd->type);
                julie_free_value(interp, cmd);
                goto out;
            }

            strings.push_back(strdup(julie_value_cstring(cmd)));
            julie_free_value(interp, cmd);
        }

        for (unsigned i = 1; i < n_values; i += 1) {
            Julie_Value *ev = NULL;
            status = julie_eval(interp, values[i], &ev);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out_free;
            }
            strings.push_back(julie_to_string(interp, ev, JULIE_NO_QUOTE));
            julie_free_value(interp, ev);
        }

        {
            auto lock = julie->pause_yed_thread_scoped();
            int n = strings.size() - 1;
            yed_execute_command(strings[0], n, n == 0 ? NULL : &strings[1]);
        }

        *result = julie_nil_value(interp);

out_free:;
        for (char *s : strings) { free(s); }

out:;
        return status;
    }

    static Julie_Status _command(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
        Julie_Status  status = JULIE_SUCCESS;

        *result = NULL;

        if (n_values < 1) {
            status = JULIE_ERR_ARITY;
            julie_make_arity_error(interp, expr, 1, n_values, 1);
            goto out;
        }

        {
            Julie_Value *sym = values[0];

            if (sym->type != JULIE_SYMBOL) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[0], JULIE_SYMBOL, (Julie_Type)sym->type);
                *result = NULL;
                goto out;
            }

            yed_plugin_set_command(Self, julie_value_cstring(sym), cmd_dispatch);
        }

        *result = julie_nil_value(interp);

out:;
        return status;
    }

    static Julie_Status _cprint(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
        Julie_Status status = JULIE_SUCCESS;

        *result = NULL;

        if (n_values != 1) {
            status = JULIE_ERR_ARITY;
            julie_make_arity_error(interp, expr, 1, n_values, 0);
            goto out;
        }

        {
            Julie_Value *message = NULL;
            status = julie_eval(interp, values[0], &message);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out;
            }
            if (message->type != JULIE_STRING) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)message->type);
                julie_free_value(interp, message);
                goto out;
            }

            {
                auto lock = julie->pause_yed_thread_scoped();

                LOG_CMD_ENTER("julie");
                yed_cprint("%s", julie_value_cstring(message));
                LOG_EXIT();
            }
            julie_free_value(interp, message);
        }

        *result = julie_nil_value(interp);

out:;
        return status;
    }

    static Julie_Status _cerr(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
        Julie_Status status = JULIE_SUCCESS;

        *result = NULL;

        if (n_values != 1) {
            status = JULIE_ERR_ARITY;
            julie_make_arity_error(interp, expr, 1, n_values, 0);
            goto out;
        }

        {
            Julie_Value *message = NULL;
            status = julie_eval(interp, values[0], &message);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out;
            }
            if (message->type != JULIE_STRING) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)message->type);
                julie_free_value(interp, message);
                goto out;
            }

            {
                auto lock = julie->pause_yed_thread_scoped();

                LOG_CMD_ENTER("julie");
                yed_cerr("%s", julie_value_cstring(message));
                LOG_EXIT();
            }
            julie_free_value(interp, message);
        }

        *result = julie_nil_value(interp);

out:;
        return status;
    }


    static Julie_Status _buff_nlines(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
        Julie_Status status = JULIE_SUCCESS;

        *result = NULL;

        std::string buffname;
        int n_lines = 0;

        if (n_values != 1) {
            status = JULIE_ERR_ARITY;
            julie_make_arity_error(interp, expr, 1, n_values, 0);
            goto out;
        }

        {
            Julie_Value *name = NULL;
            status = julie_eval(interp, values[0], &name);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out;
            }
            if (name->type != JULIE_STRING) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)name->type);
                julie_free_value(interp, name);
                goto out;
            }

            buffname = julie_value_cstring(name);
            julie_free_value(interp, name);
        }

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_buffer *buff = yed_get_buffer((char*)buffname.c_str());
            if (buff != NULL) {
                n_lines = yed_buff_n_lines(buff);
            }
        }

        *result = julie_sint_value(interp, n_lines);

out:;
        return status;
    }

    static Julie_Status _buff_line(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
        Julie_Status status = JULIE_SUCCESS;

        *result = NULL;

        std::string buffname;
        int         row = 0;

        if (n_values != 2) {
            status = JULIE_ERR_ARITY;
            julie_make_arity_error(interp, expr, 2, n_values, 0);
            goto out;
        }

        {
            Julie_Value *name = NULL;
            status = julie_eval(interp, values[0], &name);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out;
            }
            if (name->type != JULIE_STRING) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)name->type);
                julie_free_value(interp, name);
                goto out;
            }

            buffname = julie_value_cstring(name);
            julie_free_value(interp, name);
        }

        {
            Julie_Value *ln = NULL;
            status = julie_eval(interp, values[1], &ln);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out;
            }
            if (!JULIE_TYPE_IS_INTEGER(ln->type)) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[1], _JULIE_INTEGER, (Julie_Type)ln->type);
                julie_free_value(interp, ln);
                goto out;
            }

            row = ln->type == JULIE_SINT ? (int)ln->sint : (int)ln->uint;
            julie_free_value(interp, ln);
        }

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_buffer *buff = yed_get_buffer((char*)buffname.c_str());

            auto line = buff == NULL ? NULL : yed_buff_get_line(buff, row);

            if (line == NULL) {
                *result = julie_nil_value(interp);
            } else {
                array_zero_term(line->chars);
                *result = julie_string_value_known_size(interp, (const char*)line->chars.data, line->chars.used);
            }
        }

out:;
        return status;
    }

    static Julie_Status _buff_lines(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
        Julie_Status status = JULIE_SUCCESS;

        *result = NULL;

        std::string buffname;

        if (n_values != 1) {
            status = JULIE_ERR_ARITY;
            julie_make_arity_error(interp, expr, 1, n_values, 0);
            goto out;
        }

        {
            Julie_Value *name = NULL;
            status = julie_eval(interp, values[0], &name);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out;
            }
            if (name->type != JULIE_STRING) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)name->type);
                julie_free_value(interp, name);
                goto out;
            }

            buffname = julie_value_cstring(name);
            julie_free_value(interp, name);
        }

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_buffer *buff = yed_get_buffer((char*)buffname.c_str());

            if (buff == NULL) {
                *result = julie_nil_value(interp);
            } else {
                *result = julie_list_value(interp);
                yed_line *line = NULL;
                bucket_array_traverse(buff->lines, line) {
                    array_zero_term(line->chars);
                    JULIE_ARRAY_PUSH((*result)->list, julie_string_value_known_size(interp, (const char*)line->chars.data, line->chars.used));
                }
            }
        }

out:;
        return status;
    }

    static Julie_Status _activate_frame(Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) {
        Julie_Status status = JULIE_SUCCESS;

        *result = NULL;

        if (n_values != 1) {
            status = JULIE_ERR_ARITY;
            julie_make_arity_error(interp, expr, 1, n_values, 0);
            goto out;
        }

        {
            Julie_Value *idx = NULL;
            status = julie_eval(interp, values[0], &idx);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                goto out;
            }
            if (!JULIE_TYPE_IS_INTEGER(idx->type)) {
                status = JULIE_ERR_TYPE;
                julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
                julie_free_value(interp, idx);
                goto out;
            }

            {
                auto lock = julie->pause_yed_thread_scoped();

                yed_frame *frame = get_frame(idx->type == JULIE_SINT ? idx->sint : idx->uint);
                if (frame != NULL) {
                    yed_activate_frame(frame);
                }
            }
            julie_free_value(interp, idx);
        }

        *result = julie_nil_value(interp);

out:;
        return status;
    }

    static void cmd_dispatch(int n_args, char **args) {
        char  *cmd      = strdup(julie->cmd_dispatch_name.c_str());
        char **args_cpy = (char**)malloc(n_args * sizeof(*args));

        for (int i = 0; i < n_args; i += 1) {
            args_cpy[i] = strdup(args[i]);
        }

        {
            Eval_Synchronizer sync;
            julie->interp_messages.push({ .type = INTERP_MESSAGE_CMD, .cmd = { .cmd = cmd, .n_args = n_args, .args = args_cpy } });
        }

        julie->handle_yed_thread();
    }

public:
    Julie() {
    }

    void init() {
        this->interp_thread = std::thread(interp_thread_main);
    }

    ~Julie() {
        teardown = true;
        this->yed_thread_relinquish();
        this->interp_messages.push({ .type = INTERP_MESSAGE_STOP });
        this->interp_thread.join();
    }

    void yed_thread_relinquish() {
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

//                     LOG_CMD_ENTER("julie");
//                     int len = strlen(msg->output.str);
//                     if (len > 0 && msg->output.str[len - 1] == '\n') {
//                         msg->output.str[len - 1] = 0;
//                     }
//                     yed_log("%s", msg->output.str);
//                     LOG_EXIT();

                    free(msg->output.str);
                    break;
                }
            }
        }
        this->pump_requested = false;
        if (this->n_queued_for_sync > 0) {
            yed_force_update();
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

    void set_cmd_dispatch_name(const char *name) {
        this->cmd_dispatch_name = name;
    }

    yed_command get_cmd_dispatch_fn() {
        return this->cmd_dispatch;
    }

    struct Eval_Synchronizer {
        Eval_Synchronizer() {
            std::unique_lock eval_lock(julie->eval_mtx);
            std::unique_lock sync_lock(julie->yed_sync_mtx);
            julie->eval_running    = true;
            julie->yed_thread_free = true;
            sync_lock.unlock();
            julie->yed_sync_cond.notify_all();
        }
        ~Eval_Synchronizer() {
            std::unique_lock eval_lock(julie->eval_mtx);
            while (julie->eval_running) {
                julie->eval_cond.wait(eval_lock);
            }
            std::unique_lock sync_lock(julie->yed_sync_mtx);
            julie->yed_thread_free = false;
        }
    };

    void eval_string(const char *code_string) {
        {
            Eval_Synchronizer sync;
            this->interp_messages.push({ .type = INTERP_MESSAGE_EVAL, .eval = { .code = strdup(code_string) } });
        }
        this->handle_yed_thread();
    }

    void run_on_key(yed_event *event) {
        this->setup_current_event(event);
        {
            Eval_Synchronizer sync;
            this->interp_messages.push({ .type = INTERP_MESSAGE_EVENT, .event = { .kind = event->kind } });
        }
        this->handle_yed_thread();
    }
};




static Julie                  _julie;
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
    julie->run_on_key(event);
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

static void cmdrun(yed_event *event) {
    yed_command cmd = yed_get_command(event->cmd_name);
    if (cmd != julie->get_cmd_dispatch_fn()) { return; }

    julie->set_cmd_dispatch_name(event->cmd_name);
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

    h.kind = EVENT_BUFFER_POST_MOD;
    h.fn   = buffmod;
    yed_plugin_add_event_handler(self, h);

    h.kind = EVENT_CMD_PRE_RUN;
    h.fn   = cmdrun;
    yed_plugin_add_event_handler(self, h);

    if (yed_get_var("julie-debug-log") == NULL) {
        yed_set_var("julie-debug-log", "yes");
    }

    yed_plugin_set_command(self, "julie-prompt", cmd_prompt);
    yed_plugin_set_command(self, "julie-eval",   cmd_eval);

    julie = &_julie;
    julie->init();

    return 0;
}

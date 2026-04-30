#pragma once

#include <memory>
#include <functional>
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


class Binding_Registry {
    Binding_Registry() = default;

public:
    using Binding_Fn = Julie_Status(*)(Julie_Interp*, Julie_Value*, unsigned, Julie_Value**, Julie_Value**);

    std::unordered_map<std::string, Binding_Fn> bindings;

    static Binding_Registry& get();
    void register_binding(const std::string &name, Binding_Fn fn);
};

struct Binding_Registrar {
    Binding_Registrar(const std::string &name, Binding_Registry::Binding_Fn fn);
};

#define _REGISTER_BINDING_ID(uniq) _binding_##uniq
#define REGISTER_BINDING_ID(uniq) _REGISTER_BINDING_ID(uniq)
#define REGISTER_BINDING(name, fn) \
    static Binding_Registrar REGISTER_BINDING_ID(__LINE__)(name, fn)

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

    void destroy();
};

enum {
    EDITOR_MESSAGE_JULIE_OUTPUT,
    EDITOR_MESSAGE_JULIE_ERROR,
};

struct Editor_Message_Output {
    char *str;
};

struct Editor_Message_Error {
    char *file;
    char *message;
    int   line;
    int   col;
};

struct Editor_Message {
    int type;
    union {
        Editor_Message_Output output;
        Editor_Message_Error  error;
    };
};


struct YED_Thread_Lock {
    std::unique_lock<std::mutex> lock;
    bool                         owned;

    YED_Thread_Lock();
    YED_Thread_Lock(std::unique_lock<std::mutex> &&lock);
    ~YED_Thread_Lock();
};

struct Error_Location {
    std::string file;
    int line = 0;
    int col  = 0;
};

struct Error_Popup {
    struct Click_Region {
        int         row;
        std::string command;
    };

    std::string                     file;
    int                             line = 0;
    int                             col  = 0;
    std::string                     message;
    bool                            active               = false;
    bool                            mouse_handler_active = false;
    int                             popup_start_c        = 0;
    int                             popup_end_c          = 0;
    std::vector<yed_direct_draw_t*> dds;
    std::vector<Click_Region>       click_regions;

    void kill_dds();
    void dismiss();
    void show(const char *f, int l, int c, const char *msg);
    void draw();

    Error_Location get_location();
};


class Julie {
    struct Current_Event_Data {
        int         kind      = 0;
        int         key       = 0;
        int         frame_idx = -1;
        int         row       = 0;
        int         col       = 0;
        std::string buffer_name;
        std::string path;
    };

    std::thread                    interp_thread;
    Message_Queue<Interp_Message>  interp_messages;
    Message_Queue<Editor_Message>  editor_messages;
    std::atomic<bool>              pump_requested = false;
    std::atomic<std::thread::id>   yed_context_owner;
    bool                           teardown = false;
    Current_Event_Data             current_event;
    std::string                    cmd_dispatch_name;
    Error_Popup                    error_popup;

public:
    bool                           yed_thread_free = false;
    std::atomic<int>               n_queued_for_sync = 0;
    std::mutex                     yed_sync_mtx;
    std::condition_variable        yed_sync_cond;
    std::mutex                     eval_mtx;
    std::condition_variable        eval_cond;
    int                            n_pending_eval = 0;

    Julie();
    ~Julie();
    void init();
    YED_Thread_Lock pause_yed_thread_scoped();
    Message_Queue<Interp_Message>& get_interp_messages();
    Message_Queue<Editor_Message>& get_editor_messages();
    void request_pump();
    bool current_thread_owns_yed_context();
    void set_yed_context_owner(std::thread::id id);
    void yed_thread_relinquish();
    Julie_Value *get_event_object(Julie_Interp *interp);
    bool is_in_teardown();
    static void cmd_dispatch(int n_args, char **args);
    void set_cmd_dispatch_name(const char *name);
    const std::string& get_cmd_dispatch_name();
    void push_interp_message(Interp_Message msg);
    void handle_yed_thread();
    void setup_current_event(yed_event *event);
    void eval_string(const char *code_string);
    void run_on_event(yed_event *event);
    bool error_popup_active();
    void dismiss_error_popup();
    Error_Location get_error_location();
    bool error_popup_handle_click(int r, int c);
};

extern Julie *julie;
extern yed_plugin *Self;

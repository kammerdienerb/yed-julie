#include <yed/plugin.h>
#include <pthread.h>
#include <inttypes.h>

#include "julie.h"

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


#define JULIE_MAX_OUTPUT_LEN (64000)

enum {
    EDITOR_MESSAGE_JULIE_OUTPUT,
};


typedef struct {
    char *code;
} Interp_Message_Eval;

typedef struct {
    int type;
    union {
        Interp_Message_Eval eval;
    };
} Interp_Message;

typedef struct {
    char *str;
} Editor_Message_Output;

typedef struct {
    int type;
    union {
        Editor_Message_Output outout;
    };
} Editor_Message;



static yed_plugin            *Self;
static Julie_Interp          *interp;
static array_t                interp_messages;
static pthread_mutex_t        interp_messages_mtx = PTHREAD_MUTEX_INITIALIZER;
static array_t                editor_messages;
static pthread_mutex_t        editor_messages_mtx = PTHREAD_MUTEX_INITIALIZER;
static array_t                julie_output_chars;
static array_t                prompt_hist;
static yed_cmd_line_readline  prompt_readline;

static send_editor(Editor_Message *msg) {
    pthread_mutex_lock(&editor_messages_mtx);
    array_push(editor_messages, *msg);
    pthread_mutex_unlock(&editor_messages_mtx);

    yed_force_update();
}

static void send_editor_output(char *str) {
    Editor_Message msg;

    msg.type       = EDITOR_MESSAGE_JULIE_OUTPUT;
    msg.output.str = str;

    send_editor(&msg);
}

static void julie_output_cb(const char *s, int n_bytes) {
    char *str;

    str = malloc(n_bytes + 1);
    memcpy(str, s, n_bytes);
    str[n_bytes] = 0;

    send_editor_output(str);

    char       *string;
    yed_buffer *output_buff;
    int         r;
    yed_line   *last_line;
    int         c;

    string = malloc(n_bytes + 1);
    memcpy(string, s, n_bytes);
    string[n_bytes] = 0;

    output_buff = yed_get_or_create_special_rdonly_buffer("*julie-output");

    r = yed_buff_n_lines(output_buff);
    if (r == 0) { r = 1; }
    last_line = yed_buff_get_line(output_buff, r);
    c = last_line->visual_width + 1;

    output_buff->flags &= ~BUFF_RD_ONLY;
    yed_buff_insert_string_no_undo(output_buff, string, r, c);
    output_buff->flags |= BUFF_RD_ONLY;

    free(string);
}

static void julie_error_cb(Julie_Error_Info *info) {
    char                  *s;
    char                   buff[1024];
    unsigned               i;
    Julie_Backtrace_Entry *it;

    s = julie_get_pretty_error_string(info, "", "", "");
    julie_output_cb(s, strlen(s));
    free(s);

/*     set_err(info->file_id != NULL, */
/*             info->file_id != NULL ? julie_get_cstring(info->file_id) : NULL, */
/*             info->line, */
/*             info->col, */
/*             err_buff); */

    snprintf(buff, sizeof(buff), "\n");
    julie_output_cb(buff, strlen(buff));

    i = 1;
    while ((it = julie_bt_entry(info->interp, i)) != NULL) {
        s = julie_to_string(info->interp, it->fn, 0);
        snprintf(buff, sizeof(buff), "    %s:%llu:%llu %s\n",
                it->file_id == NULL ? "<?>" : julie_get_cstring(it->file_id),
                it->line,
                it->col,
                s);
        free(s);
        julie_output_cb(buff, strlen(buff));

        i += 1;
    }

    julie_free_error_info(info);
}

static void create_julie_builtins(void) {
}

#if 0
static yed_attrs get_val_attrs(void) {
    yed_attrs a;
    yed_attrs blue;
    float     brightness;

    a = yed_active_style_get_active();

    if (a.bg == 0) {
        /* The user is likely using style_term_bg... use the complement of the fg. */
        a.bg = 0xffffff - a.fg;
        ATTR_SET_BG_KIND(a.flags, ATTR_KIND_RGB);
    }

    if (ATTR_FG_KIND(a.flags) == ATTR_KIND_RGB) {
        blue       = yed_active_style_get_blue();
        brightness = ((RGB_32_r(a.bg) + RGB_32_g(a.bg) + RGB_32_b(a.bg)) / 3) / 255.0f;
        a.bg       = RGB_32(RGB_32_r(blue.fg) / 2 + (u32)(brightness * 0x7f),
                            RGB_32_g(blue.fg) / 2 + (u32)(brightness * 0x7f),
                            RGB_32_b(blue.fg) / 2 + (u32)(brightness * 0x7f));
    } else {
        a = yed_parse_attrs("&active.bg &blue.fg swap");
    }

    return a;
}
#endif

#if 0
static void cmd_julie_eval(int n_args, char **args) {
    array_t       string;
    const char   *lazy_space = "";
    int           i;

    string = array_make(char);

    for (i = 0; i < n_args; i += 1) {
        array_push_n(string, (char*)lazy_space, strlen(lazy_space));
        lazy_space = " ";
        array_push_n(string, args[i], strlen(args[i]));
    }

    array_zero_term(string);


    array_free(string);
}
#endif

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
    char          *string;
    Julie_Value   *parse;
    Julie_Value   *code;
    Julie_Value   *list;
    Julie_Value   *apply;
    Julie_Status   status;
    Julie_Value   *result;
    char         **mru;

    ys->interactive_command = NULL;

    string = yed_cmd_line_readline_get_string();

    yed_clear_cmd_buff();

    parse = julie_symbol_value(interp, julie_get_string_id(interp, "parse-julie"));
    code = julie_string_value(interp, string);
    list = julie_list_value(interp);
    JULIE_ARRAY_PUSH(list->list, parse);
    JULIE_ARRAY_PUSH(list->list, code);
    apply = julie_list_value(interp);
    JULIE_ARRAY_PUSH(apply->list, list);

    status = julie_eval(interp, apply, &result);
    if (status == JULIE_SUCCESS) {
        julie_free_value(interp, result);
    }

    mru = array_last(prompt_hist);

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

static void unload(yed_plugin *self) {
    (void)self;

    if (interp != NULL) {
        julie_free(interp);
        interp = NULL;
    }
}

int yed_plugin_boot(yed_plugin *self) {


    YED_PLUG_VERSION_CHECK();

    Self = self;

    yed_plugin_set_unload_fn(self, unload);

    julie_output_chars = array_make(char);

    yed_get_or_create_special_rdonly_buffer("*julie-output");

    prompt_hist = array_make(char*);
    yed_cmd_line_readline_make(&prompt_readline, &prompt_hist);




    interp = julie_init_interp();
    julie_set_error_callback(interp,     julie_error_cb);
    julie_set_output_callback(interp,    julie_output_cb);
/*     julie_set_post_eval_callback(interp, julie_post_eval_cb); */
    create_julie_builtins();

    if (yed_get_var("julie-debug-log") == NULL) {
        yed_set_var("julie-debug-log", "yes");
    }

    yed_plugin_set_command(self, "julie-prompt", cmd_prompt);

    return 0;
}

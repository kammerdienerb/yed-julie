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
    NOT_STARTED,
    RUNNING,
    ABORTING,
    FINISHED,
};

static yed_plugin        *Self;
static char               buffname[4096];
static Julie_Interp      *interp;
static int                julie_dirty;
static u64                julie_dirty_time_ms;
static int                julie_state;
static array_t            julie_output_chars;
static u64                julie_start_time_ms;
static int                has_err;
static char               err_msg[1024];
static char               err_file[512];
static int                err_line;
static int                err_col;
static int                err_has_loc;
int                       has_val;
static char               val_str[1024];
static char               val_file[512];
static int                val_line;
static int                val_col;

static void julie_output_cb(const char *s, int n_bytes) {
    int         len;
    array_t     old;
    const char *message;

    array_push_n(julie_output_chars, (char*)s, n_bytes);
    len = array_len(julie_output_chars);
    if (len > JULIE_MAX_OUTPUT_LEN) {
        old               = julie_output_chars;
        julie_output_chars = array_make_with_cap(char, len - JULIE_MAX_OUTPUT_LEN);
        message = "... (output truncated)\n\n";
        array_push_n(julie_output_chars, (char*)message, strlen(message));
        array_push_n(julie_output_chars, array_data(old) + len - JULIE_MAX_OUTPUT_LEN, JULIE_MAX_OUTPUT_LEN);
        array_free(old);
    }
}

static void set_val(const char *file, int line, int col, const char *s) {
    has_val = 1;

    val_file[0] = 0;
    val_line    = line;
    val_col     = MAX(col, 1);
    val_str[0]  = 0;

    strncat(val_str, s, sizeof(val_str) - 1);
}

static Julie_Status julie_post_eval_cb(Julie_Status status, Julie_Value *value, Julie_Value **result) {
    const char              *message;
    Julie_Source_Value_Info *info;
    char                    *s;

    (void)value;

    if (unlikely(julie_state == ABORTING)) {
        message = "julie: TIMEOUT\n";
        julie_output_cb(message, strlen(message));
        return JULIE_ERR_EVAL_CANCELLED;
    }

    if (*result != NULL && julie_bt_entry(interp, 0) == NULL) {
        info = julie_get_source_value_info(value);
        if (info != NULL) {
            s = julie_to_string(interp, *result, 0);
            set_val(julie_get_cstring(info->file_id), info->line, info->col, s);
            free(s);
        }
    }

    return JULIE_SUCCESS;
}

static void set_err(int has_loc, const char *file, int line, int col, const char *msg) {
    has_err = 1;

    err_has_loc = has_loc;
    err_file[0] = 0;
    if (err_has_loc) {
        strcat(err_file, file);
        err_line    = line;
        err_col     = MAX(col, 1);
    }
    err_msg[0] = 0;

    strncat(err_msg, msg, sizeof(err_msg) - 1);
}

static void julie_error_cb(Julie_Error_Info *info) {
    Julie_Status           status;
    char                   buff[1024];
    char                   err_buff[1024];
    char                  *s;
    unsigned               i;
    Julie_Backtrace_Entry *it;

    status = info->status;

    snprintf(buff, sizeof(buff), "%s:%llu:%llu: error: %s",
            info->file_id == NULL ? "<?>" : julie_get_cstring(info->file_id),
            info->line,
            info->col,
            julie_error_string(status));
    julie_output_cb(buff, strlen(buff));

    err_buff[0] = 0;
    strncat(err_buff, buff, sizeof(err_buff) - strlen(err_buff) - 1);

    switch (status) {
        case JULIE_ERR_LOOKUP:
            if (info->lookup.sym != NULL) {
                snprintf(buff, sizeof(buff), " (%s)", info->lookup.sym);
                julie_output_cb(buff, strlen(buff));
            }
            break;
        case JULIE_ERR_RELEASE_WHILE_BORROWED:
            if (info->release_while_borrowed.sym != NULL) {
                snprintf(buff, sizeof(buff), " (%s)", info->release_while_borrowed.sym);
                julie_output_cb(buff, strlen(buff));
            }
            break;
        case JULIE_ERR_REF_OF_TRANSIENT:
            if (info->ref_of_transient.sym != NULL) {
                snprintf(buff, sizeof(buff), " (%s)", info->ref_of_transient.sym);
                julie_output_cb(buff, strlen(buff));
            }
            break;
        case JULIE_ERR_REF_OF_OBJECT_KEY:
            if (info->ref_of_object_key.sym != NULL) {
                snprintf(buff, sizeof(buff), " (%s)", info->ref_of_object_key.sym);
                julie_output_cb(buff, strlen(buff));
            }
            break;
        case JULIE_ERR_NOT_LVAL:
            if (info->not_lval.sym != NULL) {
                snprintf(buff, sizeof(buff), " (%s)", info->not_lval.sym);
                julie_output_cb(buff, strlen(buff));
            }
            break;
        case JULIE_ERR_MODIFY_WHILE_ITER:
            if (info->modify_while_iter.sym != NULL) {
                snprintf(buff, sizeof(buff), " (%s)", info->modify_while_iter.sym);
                julie_output_cb(buff, strlen(buff));
            }
            break;
        case JULIE_ERR_ARITY:
            snprintf(buff, sizeof(buff), " (wanted %s%llu, got %llu)",
                    info->arity.at_least ? "at least " : "",
                    info->arity.wanted_arity,
                    info->arity.got_arity);
            julie_output_cb(buff, strlen(buff));
            break;
        case JULIE_ERR_TYPE:
            snprintf(buff, sizeof(buff), " (wanted %s, got %s)",
                    julie_type_string(info->type.wanted_type),
                    julie_type_string(info->type.got_type));
            julie_output_cb(buff, strlen(buff));
            break;
        case JULIE_ERR_BAD_APPLY:
            snprintf(buff, sizeof(buff), " (got %s)", julie_type_string(info->bad_application.got_type));
            julie_output_cb(buff, strlen(buff));
            break;
        case JULIE_ERR_BAD_INDEX:
            s = julie_to_string(info->interp, info->bad_index.bad_index, 0);
            snprintf(buff, sizeof(buff), " (index: %s)", s);
            free(s);
            julie_output_cb(buff, strlen(buff));
            break;
        case JULIE_ERR_FILE_NOT_FOUND:
        case JULIE_ERR_FILE_IS_DIR:
        case JULIE_ERR_MMAP_FAILED:
            snprintf(buff, sizeof(buff), " (%s)", info->file.path);
            julie_output_cb(buff, strlen(buff));
            break;
        case JULIE_ERR_LOAD_PACKAGE_FAILURE:
            snprintf(buff, sizeof(buff), " (%s) %s", info->load_package_failure.path, info->load_package_failure.package_error_message);
            julie_output_cb(buff, strlen(buff));
            break;
        default:
            buff[0] = 0;
            break;
    }

    strncat(err_buff, buff, sizeof(err_buff) - strlen(err_buff) - 1);

    set_err(info->file_id != NULL,
            info->file_id != NULL ? julie_get_cstring(info->file_id) : NULL,
            info->line,
            info->col,
            err_buff);

    snprintf(buff, sizeof(buff), "\n");
    julie_output_cb(buff, strlen(buff));

    i = 1;
    while ((it = julie_bt_entry(interp, i)) != NULL) {
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

static void on_julie_update(void) {
    julie_dirty         = 1;
    julie_dirty_time_ms = measure_time_now_ms();
}

static void create_julie_builtins(Julie_Interp *interp) {
}

static void *julie_timeout_thread(void *arg) {
    u64 now;

    (void)arg;

    for (;;) {
        if (julie_state != RUNNING) { break; }

        usleep(100000);

        now = measure_time_now_ms();

        if (now - julie_start_time_ms > 2500) {
            julie_state = ABORTING;
            break;
        }
    }

    return NULL;
}

static void *julie_thread(void *arg) {
    char        *code;
    Julie_Status  status;

    code = arg;

    array_free(julie_output_chars);
    julie_output_chars = array_make_with_cap(char, JULIE_MAX_OUTPUT_LEN);

    interp = julie_init_interp();
    julie_set_error_callback(interp,     julie_error_cb);
    julie_set_output_callback(interp,    julie_output_cb);
    julie_set_post_eval_callback(interp, julie_post_eval_cb);
    julie_set_cur_file(interp, julie_get_string_id(interp, buffname));

    create_julie_builtins(interp);

    status = julie_parse(interp, code, strlen(code));
    if (status == JULIE_SUCCESS) {
        julie_interp(interp);
    }

    free(code);

    julie_state = FINISHED;

    yed_force_update();

    return NULL;
}

static yed_attrs get_err_attrs(void) {
    yed_attrs a;
    yed_attrs red;
    float     brightness;

    a = yed_active_style_get_active();

    if (a.bg == 0) {
        /* The user is likely using style_term_bg... use the complement of the fg. */
        a.bg = 0xffffff - a.fg;
        ATTR_SET_BG_KIND(a.flags, ATTR_KIND_RGB);
    }

    if (ATTR_FG_KIND(a.flags) == ATTR_KIND_RGB) {
        red        = yed_active_style_get_red();
        brightness = ((RGB_32_r(a.bg) + RGB_32_g(a.bg) + RGB_32_b(a.bg)) / 3) / 255.0f;
        a.bg       = RGB_32(RGB_32_r(red.fg) / 2 + (u32)(brightness * 0x7f),
                            RGB_32_g(red.fg) / 2 + (u32)(brightness * 0x7f),
                            RGB_32_b(red.fg) / 2 + (u32)(brightness * 0x7f));
    } else {
        a = yed_parse_attrs("&active.bg &red.fg swap");
    }

    return a;
}

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

static void update_julie(void) {
    pthread_t   t;
    yed_buffer *buff;
    char       *code;

    if (julie_state != NOT_STARTED) { return; }

    if ((buff = yed_get_buffer(buffname)) != NULL) {
        has_err = 0;
        has_val = 0;

        DBG("starting Julie interpreter");

        code = yed_get_buffer_text(buff);

        buff = yed_get_or_create_special_rdonly_buffer("*julie-output");
        buff->flags &= ~BUFF_RD_ONLY;
        yed_buff_clear_no_undo(buff);
        buff->flags |= BUFF_RD_ONLY;

        julie_state = RUNNING;
        julie_start_time_ms = measure_time_now_ms();
        pthread_create(&t, NULL, julie_thread, code);
        pthread_detach(t);
        pthread_create(&t, NULL, julie_timeout_thread, code);
        pthread_detach(t);
        yed_force_update();
    }

    julie_dirty = 0;
}

static void after_julie(void) {
    yed_buffer *b;

    b = yed_get_or_create_special_rdonly_buffer("*julie-output");

    b->flags &= ~BUFF_RD_ONLY;
    yed_buff_clear_no_undo(b);
    array_zero_term(julie_output_chars);
    yed_buff_insert_string_no_undo(b, array_data(julie_output_chars), 1, 1);
    array_clear(julie_output_chars);
    b->flags |= BUFF_RD_ONLY;

    julie_free(interp);

    yed_force_update();
}

static void epump(yed_event *event) {
    u64 now;

    (void)event;

    if (julie_state == FINISHED) {
        after_julie();
        julie_state = NOT_STARTED;
    }

    if (julie_dirty) {
        now = measure_time_now_ms();
        if (now - julie_dirty_time_ms >= 500) {
            update_julie();
        }
    }
}

static void ewrite(yed_event *event) {
    if (event->buffer == NULL) { return; }

    if (strcmp(event->buffer->name, buffname) == 0) {
        update_julie();
    }
}

static void ebuffmod(yed_event *event) {
    if (event->buffer == NULL) { return; }

    if (strcmp(event->buffer->name, buffname) == 0) {
        has_err = 0;
        has_val = 0;

        if (yed_var_is_truthy("julie-live-update")) {
            on_julie_update();
        }
    }
}

static void print_line_info(yed_frame *frame, yed_attrs attrs, int row, int col, const char *message) {
    yed_attrs  b_attrs;
    yed_line  *line;
    int        screen_row;
    char       chopped[4096];
    int        space_avail;
    int        l;
    float      p;
    yed_glyph *git;
    int        er;
    int        eg;
    int        eb;
    int        ar;
    int        ag;
    int        ab;

    b_attrs = frame == ys->active_frame ? yed_active_style_get_active() : yed_active_style_get_inactive();
    if (b_attrs.bg == 0) {
        /* The user is likely using style_term_bg... use the complement of the fg. */
        b_attrs.bg = 0xffffff - b_attrs.fg;
        ATTR_SET_BG_KIND(b_attrs.flags, ATTR_KIND_RGB);
    }

    line = yed_buff_get_line(frame->buffer, row);
    if (line == NULL) { return; }

    screen_row = frame->top + (row - frame->buffer_y_offset) - 1;

    chopped[0] = 0;
    strncat(chopped, " ", sizeof(chopped) - strlen(chopped) - 1);
    strncat(chopped, message, sizeof(chopped) - strlen(chopped) - 1);
    strncat(chopped, " ", sizeof(chopped) - strlen(chopped) - 1);

    space_avail = 1 + frame->width - (line->visual_width + 8 - frame->buffer_x_offset);
    if (yed_get_string_width(chopped) > space_avail) {
        space_avail -= 3;
        do {
            chopped[strlen(chopped) - 1] = 0;
        } while (*chopped && yed_get_string_width(chopped) > space_avail);
        strncat(chopped, "...", sizeof(chopped) - strlen(chopped) - 1);
    }

    yed_set_attr(attrs);

    l   = frame->left + line->visual_width + 8 - frame->buffer_x_offset - 1;
    p   = 0.005;
    git = NULL;

#define STEP_P()                                        \
    if (ATTR_BG_KIND(attrs.flags)   == ATTR_KIND_RGB    \
    &&  ATTR_BG_KIND(b_attrs.flags) == ATTR_KIND_RGB) { \
                                                        \
        er = (int)((1.0 - p) * RGB_32_r(attrs.bg));     \
        eg = (int)((1.0 - p) * RGB_32_g(attrs.bg));     \
        eb = (int)((1.0 - p) * RGB_32_b(attrs.bg));     \
        ar = (int)(p * RGB_32_r(b_attrs.bg));           \
        ag = (int)(p * RGB_32_g(b_attrs.bg));           \
        ab = (int)(p * RGB_32_b(b_attrs.bg));           \
        attrs.bg = RGB_32(er + ar, eg + ag, eb + ab);   \
        yed_set_attr(attrs);                            \
                                                        \
        p *= 1.05;                                      \
        if (p > 1.0) { p = 1.0; }                       \
    }

    yed_glyph_traverse(chopped, git) {
        STEP_P();
        yed_set_cursor(screen_row, l);
        yed_screen_print_single_cell_glyph_over(git);
        l += yed_get_glyph_width(git);
    }

    for (; l <= frame->left + frame->width - 1; l += 1) {
        STEP_P();
        yed_set_cursor(screen_row, l);
        yed_screen_print_over(" ");
    }
}

static void eupdate(yed_event *event) {
    int       i;
    int       row;
    yed_attrs attrs;

    if (!has_err && !has_val) { return; }

    if (event->frame != ys->active_frame) { return; }

    if (ys->active_frame->buffer == NULL) { return; }

    if (strcmp(ys->active_frame->buffer->name, buffname) != 0) {
        return;
    }

    if (has_err) {
        for (i = 1; i <= event->frame->height; i += 1) {
            row = event->frame->buffer_y_offset + i;

            if (row == err_line) {
                attrs = get_err_attrs();
                print_line_info(event->frame, attrs, err_line, err_col, err_msg);
                break;
            }
        }
    } else if (has_val) {
        for (i = 1; i <= event->frame->height; i += 1) {
            row = event->frame->buffer_y_offset + i;

            if (row == val_line) {
                attrs = get_val_attrs();
                print_line_info(event->frame, attrs, val_line, val_col, val_str);
                break;
            }
        }
    }
}

static void evar(yed_event *event) {
    char  a_path[4096];
    char  r_path[4096];
    char  h_path[4096];
    char *name;

    if (strcmp(event->var_name, "julie-interactive-file") == 0) {
        abs_path(event->var_val, a_path);
        relative_path_if_subtree(a_path, r_path);
        if (homeify_path(r_path, h_path)) {
            name = h_path;
        } else {
            name = r_path;
        }
        strncpy(buffname, name, sizeof(buffname));
    }
}

static void unload(yed_plugin *self) {
    (void)self;
}

int yed_plugin_boot(yed_plugin *self) {
    yed_event_handler  pump_handler;
    yed_event_handler  buffmod_handler;
    yed_event_handler  write_handler;
    yed_event_handler  update_handler;
    yed_event_handler  var_handler;
    char              *path;

    YED_PLUG_VERSION_CHECK();

    Self = self;

    yed_plugin_set_unload_fn(self, unload);

    pump_handler.kind = EVENT_PRE_PUMP;
    pump_handler.fn   = epump;
    yed_plugin_add_event_handler(self, pump_handler);

    buffmod_handler.kind = EVENT_BUFFER_POST_MOD;
    buffmod_handler.fn   = ebuffmod;
    yed_plugin_add_event_handler(self, buffmod_handler);

    write_handler.kind = EVENT_BUFFER_POST_WRITE;
    write_handler.fn   = ewrite;
    yed_plugin_add_event_handler(self, write_handler);

    update_handler.kind = EVENT_FRAME_POST_UPDATE;
    update_handler.fn   = eupdate;
    yed_plugin_add_event_handler(self, update_handler);

    var_handler.kind = EVENT_VAR_POST_SET;
    var_handler.fn   = evar;
    yed_plugin_add_event_handler(self, var_handler);

    if (yed_get_var("julie-live-update") == NULL) {
        yed_set_var("julie-live-update", "yes");
    }
    if (yed_get_var("julie-interactive-file") == NULL) {
        path = get_config_item_path("julie.j");
        yed_set_var("julie-interactive-file", path);
        free(path);
    }

    yed_set_var("debug-log", "yes");

    yed_get_or_create_special_rdonly_buffer("*julie-output");

    YEXE("buffer-hidden", buffname);

    return 0;
}

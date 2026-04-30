#include "plugin.hpp"

REGISTER_BINDING("@buffer-line", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
});

REGISTER_BINDING("@buffer-line", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
});

REGISTER_BINDING("@buffer-lines", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
});

REGISTER_BINDING("@buffer-exists", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        Julie_Value *name = NULL;
        status = julie_eval(interp, values[0], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            *result = julie_sint_value(interp, yed_get_buffer((char*)buffname.c_str()) != NULL);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@buffer-is-special", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        Julie_Value *name = NULL;
        status = julie_eval(interp, values[0], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_buffer *buff = yed_get_buffer((char*)buffname.c_str());
            int is_special = buff != NULL && (buff->flags & BUFF_SPECIAL);
            *result = julie_sint_value(interp,  is_special);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@buffer-ft", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        Julie_Value *name = NULL;
        status = julie_eval(interp, values[0], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_buffer *buff = yed_get_buffer((char*)buffname.c_str());
            if (buff != NULL) {
                char *ft_name = yed_get_ft_name(buff->ft);
                *result = ft_name ? julie_string_value(interp, ft_name) : julie_nil_value(interp);
            } else {
                *result = julie_nil_value(interp);
            }
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@buffer-path", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        Julie_Value *name = NULL;
        status = julie_eval(interp, values[0], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_buffer *buff = yed_get_buffer((char*)buffname.c_str());
            *result = (buff != NULL && buff->path != NULL)
                ? julie_string_value(interp, buff->path)
                : julie_nil_value(interp);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@buffer-selection-kind", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        Julie_Value *name = NULL;
        status = julie_eval(interp, values[0], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_buffer *buff = yed_get_buffer((char*)buffname.c_str());

            if (buff == NULL || !buff->has_selection) {
                *result = julie_nil_value(interp);
            } else {
                const char *s = NULL;
                switch (buff->selection.kind) {
                    case RANGE_NORMAL: s = "'normal"; break;
                    case RANGE_LINE:   s = "'line";   break;
                    case RANGE_RECT:   s = "'rect";   break;
                }
                *result = julie_symbol_value(interp, julie_get_string_id(interp, s));
            }
        }
    }

out:;
    return status;
});

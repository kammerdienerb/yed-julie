#include "plugin.hpp"

REGISTER_BINDING("@get-var", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
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

        std::string varname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            char *val = yed_get_var(varname.c_str());
            *result = val ? julie_string_value(interp, val) : julie_nil_value(interp);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@set-var", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 0);
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
        std::string varname = julie_value_cstring(name);
        julie_free_value(interp, name);

        Julie_Value *val = NULL;
        status = julie_eval(interp, values[1], &val);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        char *valstr = julie_to_string(interp, val, JULIE_NO_QUOTE);
        julie_free_value(interp, val);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_set_var(varname.c_str(), valstr);
        }
        free(valstr);
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

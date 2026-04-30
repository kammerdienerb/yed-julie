#include "plugin.hpp"

REGISTER_BINDING("@yexe", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
});

REGISTER_BINDING("@command", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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

        yed_plugin_set_command(Self, julie_value_cstring(sym), Julie::cmd_dispatch);
    }

    *result = julie_nil_value(interp);

out:;
    return status;
});

REGISTER_BINDING("@cprint", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
});

REGISTER_BINDING("@cerr", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
});

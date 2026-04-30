#include "plugin.hpp"

/* Evaluate arg at arg_idx as a string, parse it into keys. Returns n_keys
** (>0) on success, sets status and *result on failure. */
static int eval_key_string(Julie_Interp *interp, Julie_Value *expr,
                            unsigned n_values, Julie_Value **values,
                            Julie_Status *status, Julie_Value **result,
                            int *keys_out, unsigned arg_idx = 0) {
    Julie_Value *sv = NULL;
    *status = julie_eval(interp, values[arg_idx], &sv);
    if (*status != JULIE_SUCCESS) { *result = NULL; return -1; }
    if (sv->type != JULIE_STRING) {
        *status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[arg_idx], JULIE_STRING, (Julie_Type)sv->type);
        julie_free_value(interp, sv);
        *result = NULL;
        return -1;
    }
    std::string key_str = julie_value_cstring(sv);
    julie_free_value(interp, sv);

    int n;
    {
        auto lock = julie->pause_yed_thread_scoped();
        n = yed_string_to_keys(key_str.c_str(), keys_out);
    }

    if (n <= 0) {
        *status = JULIE_SUCCESS;
        *result = julie_error_value(interp, n == -2 ? "key sequence too long" : "invalid key string");
        return -1;
    }
    return n;
}

/* Helper: evaluate arg at arg_idx as a string. Returns the string on
** success, sets status and result on failure, returns "" on failure. */
static std::string eval_string_arg(Julie_Interp *interp, Julie_Value *expr,
                                    Julie_Value **values,
                                    Julie_Status *status, Julie_Value **result,
                                    unsigned arg_idx) {
    Julie_Value *sv = NULL;
    *status = julie_eval(interp, values[arg_idx], &sv);
    if (*status != JULIE_SUCCESS) { *result = NULL; return ""; }
    if (sv->type != JULIE_STRING) {
        *status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[arg_idx], JULIE_STRING, (Julie_Type)sv->type);
        julie_free_value(interp, sv);
        *result = NULL;
        return "";
    }
    std::string s = julie_value_cstring(sv);
    julie_free_value(interp, sv);
    return s;
}

REGISTER_BINDING("@add-key-sequence", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys);
        if (n < 0) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        yed_plugin_add_key_sequence(Self, n, keys);
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@delete-key-sequence", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys);
        if (n < 0) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        int seq_key = yed_get_key_sequence(n, keys);
        if (seq_key != KEY_NULL) {
            yed_delete_key_sequence(seq_key);
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@enable-key-sequence", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys);
        if (n < 0) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        int seq_key = yed_get_key_sequence(n, keys);
        if (seq_key != KEY_NULL) {
            yed_enable_key_sequence(seq_key);
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@disable-key-sequence", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys);
        if (n < 0) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        int seq_key = yed_get_key_sequence(n, keys);
        if (seq_key != KEY_NULL) {
            yed_disable_key_sequence(seq_key);
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@is-key-sequence-enabled", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys);
        if (n < 0) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        int seq_key = yed_get_key_sequence(n, keys);
        if (seq_key != KEY_NULL) {
            *result = julie_sint_value(interp, yed_is_key_sequence_enabled(seq_key));
        } else {
            *result = julie_sint_value(interp, 0);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@bind-key", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values < 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 1);
        goto out;
    }

    {
        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys);
        if (n < 0) { goto out; }

        /* evaluate command name */
        Julie_Value *cmd_val = NULL;
        status = julie_eval(interp, values[1], &cmd_val);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (cmd_val->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[1], JULIE_STRING, (Julie_Type)cmd_val->type);
            julie_free_value(interp, cmd_val);
            goto out;
        }
        std::string cmd_name = julie_value_cstring(cmd_val);
        julie_free_value(interp, cmd_val);

        /* evaluate extra args */
        std::vector<char *> cmd_args;
        for (unsigned i = 2; i < n_values; i += 1) {
            Julie_Value *av = NULL;
            status = julie_eval(interp, values[i], &av);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                for (auto *s : cmd_args) { free(s); }
                goto out;
            }
            cmd_args.push_back(julie_to_string(interp, av, JULIE_NO_QUOTE));
            julie_free_value(interp, av);
        }

        {
            auto lock = julie->pause_yed_thread_scoped();

            int bind_key;
            if (n == 1) {
                bind_key = keys[0];
            } else {
                bind_key = yed_get_key_sequence(n, keys);
                if (bind_key == KEY_NULL) {
                    for (auto *s : cmd_args) { free(s); }
                    *result = julie_error_value(interp, "key sequence not registered — call add-key-sequence first");
                    goto out;
                }
            }

            yed_plugin_bind_key(Self, bind_key, cmd_name.c_str(),
                                (int)cmd_args.size(),
                                cmd_args.empty() ? NULL : cmd_args.data());
        }

        for (auto *s : cmd_args) { free(s); }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@unbind-key", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys);
        if (n < 0) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();

        int unbind_key;
        if (n == 1) {
            unbind_key = keys[0];
        } else {
            unbind_key = yed_get_key_sequence(n, keys);
            if (unbind_key == KEY_NULL) { goto done; }
        }
        yed_unbind_key(unbind_key);
    done:;
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@key-code", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys);
        if (n < 0) { goto out; }

        if (n == 1) {
            *result = julie_sint_value(interp, keys[0]);
        } else {
            auto lock = julie->pause_yed_thread_scoped();
            int seq_key = yed_get_key_sequence(n, keys);
            *result = seq_key != KEY_NULL
                ? julie_sint_value(interp, seq_key)
                : julie_nil_value(interp);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@add-key-map", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        std::string name = eval_string_arg(interp, expr, values, &status, result, 0);
        if (status != JULIE_SUCCESS) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        yed_plugin_add_key_map(Self, name.c_str());
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@remove-key-map", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        std::string name = eval_string_arg(interp, expr, values, &status, result, 0);
        if (status != JULIE_SUCCESS) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        yed_remove_key_map(name.c_str());
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@enable-key-map", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        std::string name = eval_string_arg(interp, expr, values, &status, result, 0);
        if (status != JULIE_SUCCESS) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        yed_enable_key_map(name.c_str());
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@disable-key-map", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        std::string name = eval_string_arg(interp, expr, values, &status, result, 0);
        if (status != JULIE_SUCCESS) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();
        yed_disable_key_map(name.c_str());
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@map-bind-key", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values < 3) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 3, n_values, 1);
        goto out;
    }

    {
        std::string mapname = eval_string_arg(interp, expr, values, &status, result, 0);
        if (status != JULIE_SUCCESS) { goto out; }

        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys, 1);
        if (n < 0) { goto out; }

        Julie_Value *cmd_val = NULL;
        status = julie_eval(interp, values[2], &cmd_val);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (cmd_val->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[2], JULIE_STRING, (Julie_Type)cmd_val->type);
            julie_free_value(interp, cmd_val);
            goto out;
        }
        std::string cmd_name = julie_value_cstring(cmd_val);
        julie_free_value(interp, cmd_val);

        std::vector<char *> cmd_args;
        for (unsigned i = 3; i < n_values; i += 1) {
            Julie_Value *av = NULL;
            status = julie_eval(interp, values[i], &av);
            if (status != JULIE_SUCCESS) {
                *result = NULL;
                for (auto *s : cmd_args) { free(s); }
                goto out;
            }
            cmd_args.push_back(julie_to_string(interp, av, JULIE_NO_QUOTE));
            julie_free_value(interp, av);
        }

        {
            auto lock = julie->pause_yed_thread_scoped();

            int bind_key;
            if (n == 1) {
                bind_key = keys[0];
            } else {
                bind_key = yed_get_key_sequence(n, keys);
                if (bind_key == KEY_NULL) {
                    for (auto *s : cmd_args) { free(s); }
                    *result = julie_error_value(interp, "key sequence not registered — call add-key-sequence first");
                    goto out;
                }
            }

            yed_plugin_map_bind_key(Self, mapname.c_str(), bind_key, cmd_name.c_str(),
                                    (int)cmd_args.size(),
                                    cmd_args.empty() ? NULL : cmd_args.data());
        }

        for (auto *s : cmd_args) { free(s); }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@map-unbind-key", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 0);
        goto out;
    }

    {
        std::string mapname = eval_string_arg(interp, expr, values, &status, result, 0);
        if (status != JULIE_SUCCESS) { goto out; }

        int keys[MAX_SEQ_LEN];
        int n = eval_key_string(interp, expr, n_values, values, &status, result, keys, 1);
        if (n < 0) { goto out; }

        auto lock = julie->pause_yed_thread_scoped();

        int unbind_key;
        if (n == 1) {
            unbind_key = keys[0];
        } else {
            unbind_key = yed_get_key_sequence(n, keys);
            if (unbind_key == KEY_NULL) { goto done; }
        }
        yed_map_unbind_key(mapname.c_str(), unbind_key);
    done:;
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@map-get-bindings", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        std::string mapname = eval_string_arg(interp, expr, values, &status, result, 0);
        if (status != JULIE_SUCCESS) { goto out; }

        Julie_Value *object = NULL;

        {
            auto lock = julie->pause_yed_thread_scoped();

            yed_key_map_list *list;
            for (list = ys->keymap_list; list != NULL; list = list->next) {
                if (strcmp(list->map->name, mapname.c_str()) != 0) { continue; }

                object = julie_object_value(interp);

                tree_it(int, yed_key_binding_ptr_t) it;
                tree_traverse(list->map->binding_map, it) {
                    int               key     = tree_it_key(it);
                    yed_key_binding  *binding = tree_it_val(it);
                    char             *key_str = yed_keys_to_string(1, &key);

                    Julie_Value *binding_list = julie_list_value(interp);
                    JULIE_ARRAY_PUSH(binding_list->list, julie_string_value(interp, binding->cmd));
                    for (int i = 0; i < binding->n_args; i += 1) {
                        JULIE_ARRAY_PUSH(binding_list->list, julie_string_value(interp, binding->args[i]));
                    }

                    Julie_Value *key_val = julie_string_value_giveaway(interp, key_str ? key_str : strdup(""));
                    julie_object_insert_field(interp, object, key_val, binding_list, NULL);
                }
                break;
            }
        }

        *result = object ? object : julie_nil_value(interp);
    }

out:;
    return status;
});

REGISTER_BINDING("@real-keys", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 0) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 0, n_values, 0);
        goto out;
    }

    {
        Julie_Value *list = julie_list_value(interp);

        auto lock = julie->pause_yed_thread_scoped();
        for (int key = 1; key < REAL_KEY_MAX; key += 1) {
            char *s = yed_keys_to_string(1, &key);
            if (s == NULL) { continue; }
            JULIE_ARRAY_PUSH(list->list, julie_string_value_giveaway(interp, s));
        }

        *result = list;
    }

out:;
    return status;
});

REGISTER_BINDING("@sequence-keys", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 0) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 0, n_values, 0);
        goto out;
    }

    {
        Julie_Value *list = julie_list_value(interp);

        auto lock = julie->pause_yed_thread_scoped();

        yed_key_sequence *seq_it;
        array_traverse(ys->key_sequences, seq_it) {
            char *s = yed_keys_to_string(1, &seq_it->seq_key);
            if (s == NULL) { continue; }
            JULIE_ARRAY_PUSH(list->list, julie_string_value_giveaway(interp, s));
        }

        *result = list;
    }

out:;
    return status;
});

REGISTER_BINDING("@key-code-to-string", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        Julie_Value *code_val = NULL;
        status = julie_eval(interp, values[0], &code_val);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (!JULIE_TYPE_IS_INTEGER(code_val->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)code_val->type);
            julie_free_value(interp, code_val);
            goto out;
        }
        int key = code_val->type == JULIE_SINT ? (int)code_val->sint : (int)code_val->uint;
        julie_free_value(interp, code_val);

        auto lock = julie->pause_yed_thread_scoped();
        char *s = yed_keys_to_string(1, &key);
        *result = s ? julie_string_value_giveaway(interp, s) : julie_nil_value(interp);
    }

out:;
    return status;
});

#include "plugin.hpp"

REGISTER_BINDING("@num-undo-records", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;

    *result = NULL;

    std::string buffname;
    int n_records = 0;

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
            n_records = yed_num_undo_records(buff);
        }
    }

    *result = julie_sint_value(interp, n_records);

out:;
    return status;
});

REGISTER_BINDING("@start-undo-record", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 0);
        goto out;
    }

    {
        Julie_Value *idx = NULL;
        status = julie_eval(interp, values[0], &idx);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (idx->type != JULIE_NIL && !JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }
        int i = idx->type == JULIE_NIL
                    ? -1
                    : (idx->type == JULIE_SINT
                        ? (int)idx->sint
                        : (int)idx->uint);
        julie_free_value(interp, idx);

        Julie_Value *name = NULL;
        status = julie_eval(interp, values[1], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[1], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame  *frame = get_frame(i);
            yed_buffer *buff  = yed_get_buffer((char*)buffname.c_str());

            if (buff != NULL) {
                yed_start_undo_record(frame, buff);
            }
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@end-undo-record", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 0);
        goto out;
    }

    {
        Julie_Value *idx = NULL;
        status = julie_eval(interp, values[0], &idx);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (idx->type != JULIE_NIL && !JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }
        int i = idx->type == JULIE_NIL
                    ? -1
                    : (idx->type == JULIE_SINT
                        ? (int)idx->sint
                        : (int)idx->uint);
        julie_free_value(interp, idx);

        Julie_Value *name = NULL;
        status = julie_eval(interp, values[1], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[1], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame  *frame = get_frame(i);
            yed_buffer *buff  = yed_get_buffer((char*)buffname.c_str());

            if (buff != NULL) {
                yed_end_undo_record(frame, buff);
            }
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@cancel-undo-record", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 0);
        goto out;
    }

    {
        Julie_Value *idx = NULL;
        status = julie_eval(interp, values[0], &idx);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (idx->type != JULIE_NIL && !JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }
        int i = idx->type == JULIE_NIL
                    ? -1
                    : (idx->type == JULIE_SINT
                        ? (int)idx->sint
                        : (int)idx->uint);
        julie_free_value(interp, idx);

        Julie_Value *name = NULL;
        status = julie_eval(interp, values[1], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[1], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame  *frame = get_frame(i);
            yed_buffer *buff  = yed_get_buffer((char*)buffname.c_str());

            if (buff != NULL) {
                yed_cancel_undo_record(frame, buff);
            }
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@merge-undo-records", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
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
        if (buff != NULL) {
            yed_merge_undo_records(buff);
        }
    }

    *result = julie_nil_value(interp);

out:;
    return status;
});

REGISTER_BINDING("@undo", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 0);
        goto out;
    }

    {
        Julie_Value *idx = NULL;
        status = julie_eval(interp, values[0], &idx);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (!JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }
        int i = idx->type == JULIE_SINT
                    ? (int)idx->sint
                    : (int)idx->uint;
        julie_free_value(interp, idx);

        Julie_Value *name = NULL;
        status = julie_eval(interp, values[1], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[1], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame  *frame = get_frame(i);
            yed_buffer *buff  = yed_get_buffer((char*)buffname.c_str());

            if (frame != NULL && buff != NULL) {
                yed_undo(frame, buff);
            }
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@redo", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 0);
        goto out;
    }

    {
        Julie_Value *idx = NULL;
        status = julie_eval(interp, values[0], &idx);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (!JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }
        int i = idx->type == JULIE_SINT
                    ? (int)idx->sint
                    : (int)idx->uint;
        julie_free_value(interp, idx);

        Julie_Value *name = NULL;
        status = julie_eval(interp, values[1], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[1], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame  *frame = get_frame(i);
            yed_buffer *buff  = yed_get_buffer((char*)buffname.c_str());

            if (frame != NULL && buff != NULL) {
                yed_redo(frame, buff);
            }
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

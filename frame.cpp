#include "plugin.hpp"

static yed_frame *get_frame(int idx) {
    if (idx < 0 || idx >= (int)array_len(ys->frames)) { return NULL; }
    return *(yed_frame**)array_item(ys->frames, idx);
}

static int frame_to_idx(yed_frame *frame) {
    int i = 0;
    yed_frame **fit;
    array_traverse(ys->frames, fit) {
        if (*fit == frame) { return i; }
        i += 1;
    }
    return -1;
}

static yed_frame_tree *get_tree(int idx) {
    if (idx < 0 || idx >= (int)array_len(ys->frame_trees)) { return NULL; }
    return *(yed_frame_tree**)array_item(ys->frame_trees, idx);
}

static int tree_to_idx(yed_frame_tree *tree) {
    int i = 0;
    yed_frame_tree **it;
    array_traverse(ys->frame_trees, it) {
        if (*it == tree) { return i; }
        i += 1;
    }
    return -1;
}

static Julie_Value *tree_result(Julie_Interp *interp, yed_frame_tree *tree) {
    int idx = tree ? tree_to_idx(tree) : -1;
    return idx >= 0 ? julie_sint_value(interp, idx) : julie_nil_value(interp);
}

static yed_frame_tree *eval_tree_arg(Julie_Interp *interp, Julie_Value *expr, Julie_Value **values, Julie_Status *status) {
    Julie_Value *handle = NULL;
    *status = julie_eval(interp, values[0], &handle);
    if (*status != JULIE_SUCCESS) { return NULL; }
    if (!JULIE_TYPE_IS_INTEGER(handle->type)) {
        *status = JULIE_ERR_TYPE;
        julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)handle->type);
        julie_free_value(interp, handle);
        return NULL;
    }
    int idx = handle->type == JULIE_SINT ? (int)handle->sint : (int)handle->uint;
    julie_free_value(interp, handle);
    return get_tree(idx);
}

REGISTER_BINDING("@activate-frame", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
});

REGISTER_BINDING("@frame-buffer", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (!JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }

        int i = idx->type == JULIE_SINT ? (int)idx->sint : (int)idx->uint;
        julie_free_value(interp, idx);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame *frame = get_frame(i);
            *result = (frame != NULL && frame->buffer != NULL)
                ? julie_string_value(interp, frame->buffer->name)
                : julie_nil_value(interp);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@frame-name", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (!JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }

        int i = idx->type == JULIE_SINT ? (int)idx->sint : (int)idx->uint;
        julie_free_value(interp, idx);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame *frame = get_frame(i);
            *result = (frame != NULL && frame->name != NULL)
                ? julie_string_value(interp, frame->name)
                : julie_nil_value(interp);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@frame-set-name", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
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
        int i = idx->type == JULIE_SINT ? (int)idx->sint : (int)idx->uint;
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
        std::string namestr = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame *frame = get_frame(i);
            if (frame != NULL) { yed_frame_set_name(frame, namestr.c_str()); }
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@frame-find-name", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
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
        std::string namestr = julie_value_cstring(name);
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame *frame = yed_find_frame_by_name(namestr.c_str());
            if (frame != NULL) {
                int i = 0;
                yed_frame **fit;
                array_traverse(ys->frames, fit) {
                    if (*fit == frame) {
                        *result = julie_sint_value(interp, i);
                        goto out;
                    }
                    i += 1;
                }
            }
            *result = julie_nil_value(interp);
        }
    }

out:;
    return status;
});

REGISTER_BINDING("@frame-delete", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (!JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }

        int i = idx->type == JULIE_SINT ? (int)idx->sint : (int)idx->uint;
        julie_free_value(interp, idx);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame *frame = get_frame(i);
            if (frame != NULL) { yed_delete_frame(frame); }
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@frame-set-buff", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
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
        int i = idx->type == JULIE_SINT ? (int)idx->sint : (int)idx->uint;
        julie_free_value(interp, idx);

        Julie_Value *name = NULL;
        status = julie_eval(interp, values[1], &name);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (name->type != JULIE_STRING && name->type != JULIE_NIL) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[1], JULIE_STRING, (Julie_Type)name->type);
            julie_free_value(interp, name);
            goto out;
        }
        std::string buffname = name->type == JULIE_STRING ? julie_value_cstring(name) : "";
        bool        is_nil   = name->type == JULIE_NIL;
        julie_free_value(interp, name);

        {
            auto lock = julie->pause_yed_thread_scoped();
            yed_frame  *frame = get_frame(i);
            yed_buffer *buff  = is_nil ? NULL : yed_get_buffer((char*)buffname.c_str());
            if (frame != NULL) { yed_frame_set_buff(frame, buff); }
        }
    }

    *result = julie_nil_value(interp);
out:;
    return status;
});

REGISTER_BINDING("@frame-is-root", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (!JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }
        int i = idx->type == JULIE_SINT ? (int)idx->sint : (int)idx->uint;
        julie_free_value(interp, idx);

        auto lock = julie->pause_yed_thread_scoped();
        yed_frame *frame = get_frame(i);
        *result = julie_sint_value(interp, frame != NULL && yed_frame_is_tree_root(frame));
    }

out:;
    return status;
});

REGISTER_BINDING("@root-tree", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
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
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (!JULIE_TYPE_IS_INTEGER(idx->type)) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[0], _JULIE_INTEGER, (Julie_Type)idx->type);
            julie_free_value(interp, idx);
            goto out;
        }
        int i = idx->type == JULIE_SINT ? (int)idx->sint : (int)idx->uint;
        julie_free_value(interp, idx);

        auto lock = julie->pause_yed_thread_scoped();
        yed_frame *frame = get_frame(i);
        *result = frame
            ? tree_result(interp, yed_frame_tree_get_root(frame->tree))
            : julie_nil_value(interp);
    }

out:;
    return status;
});

REGISTER_BINDING("@tree-split-kind", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        auto lock = julie->pause_yed_thread_scoped();
        yed_frame_tree *tree = eval_tree_arg(interp, expr, values, &status);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        const char *sym = "'leaf";
        if (tree && !tree->is_leaf) {
            sym = tree->split_kind == FTREE_VSPLIT ? "'vsplit" : "'hsplit";
        }
        *result = julie_symbol_value(interp, julie_get_string_id(interp, sym));
    }

out:;
    return status;
});

REGISTER_BINDING("@tree-is-leaf", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        auto lock = julie->pause_yed_thread_scoped();
        yed_frame_tree *tree = eval_tree_arg(interp, expr, values, &status);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        *result = tree
            ? julie_sint_value(interp, tree->is_leaf)
            : julie_nil_value(interp);
    }

out:;
    return status;
});

REGISTER_BINDING("@tree-child", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 2) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 2, n_values, 0);
        goto out;
    }

    {
        auto lock = julie->pause_yed_thread_scoped();
        yed_frame_tree *tree = eval_tree_arg(interp, expr, values, &status);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }

        Julie_Value *which = NULL;
        status = julie_eval(interp, values[1], &which);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        if (which->type != JULIE_SYMBOL) {
            status = JULIE_ERR_TYPE;
            julie_make_type_error(interp, values[1], JULIE_SYMBOL, (Julie_Type)which->type);
            julie_free_value(interp, which);
            goto out;
        }

        Julie_String_ID sid      = julie_value_string_id(interp, which);
        Julie_String_ID s_left   = julie_get_string_id(interp, "'left");
        Julie_String_ID s_right  = julie_get_string_id(interp, "'right");
        Julie_String_ID s_top    = julie_get_string_id(interp, "'top");
        Julie_String_ID s_bottom = julie_get_string_id(interp, "'bottom");
        julie_free_value(interp, which);

        int ci = (sid == s_left || sid == s_top) ? 0 : (sid == s_right || sid == s_bottom) ? 1 : -1;

        *result = (ci >= 0 && tree && !tree->is_leaf)
            ? tree_result(interp, tree->child_trees[ci])
            : julie_nil_value(interp);
    }

out:;
    return status;
});

REGISTER_BINDING("@tree-frame", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        auto lock = julie->pause_yed_thread_scoped();
        yed_frame_tree *tree = eval_tree_arg(interp, expr, values, &status);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        int idx = (tree && tree->frame) ? frame_to_idx(tree->frame) : -1;
        *result = idx >= 0 ? julie_sint_value(interp, idx) : julie_nil_value(interp);
    }

out:;
    return status;
});

REGISTER_BINDING("@tree-prefer-left-or-topmost", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        auto lock = julie->pause_yed_thread_scoped();
        yed_frame_tree *tree = eval_tree_arg(interp, expr, values, &status);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        *result = tree
            ? tree_result(interp, yed_frame_tree_get_split_leaf_prefer_left_or_topmost(tree))
            : julie_nil_value(interp);
    }

out:;
    return status;
});

REGISTER_BINDING("@tree-prefer-right-or-bottommost", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        auto lock = julie->pause_yed_thread_scoped();
        yed_frame_tree *tree = eval_tree_arg(interp, expr, values, &status);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        *result = tree
            ? tree_result(interp, yed_frame_tree_get_split_leaf_prefer_right_or_bottommost(tree))
            : julie_nil_value(interp);
    }

out:;
    return status;
});

REGISTER_BINDING("@vsplit-tree", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        auto lock = julie->pause_yed_thread_scoped();
        yed_frame_tree *tree = eval_tree_arg(interp, expr, values, &status);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        yed_frame *frame = tree ? yed_vsplit_frame_tree(tree) : NULL;
        int idx = frame ? frame_to_idx(frame) : -1;
        *result = idx >= 0 ? julie_sint_value(interp, idx) : julie_nil_value(interp);
    }

out:;
    return status;
});

REGISTER_BINDING("@hsplit-tree", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;
    *result = NULL;

    if (n_values != 1) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 1, n_values, 0);
        goto out;
    }

    {
        auto lock = julie->pause_yed_thread_scoped();
        yed_frame_tree *tree = eval_tree_arg(interp, expr, values, &status);
        if (status != JULIE_SUCCESS) { *result = NULL; goto out; }
        yed_frame *frame = tree ? yed_hsplit_frame_tree(tree) : NULL;
        int idx = frame ? frame_to_idx(frame) : -1;
        *result = idx >= 0 ? julie_sint_value(interp, idx) : julie_nil_value(interp);
    }

out:;
    return status;
});

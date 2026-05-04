#include "plugin.hpp"

REGISTER_BINDING("@clear", [](Julie_Interp *interp, Julie_Value *expr, unsigned n_values, Julie_Value **values, Julie_Value **result) -> Julie_Status
{
    Julie_Status status = JULIE_SUCCESS;

    *result = NULL;

    if (n_values != 0) {
        status = JULIE_ERR_ARITY;
        julie_make_arity_error(interp, expr, 0, n_values, 0);
        goto out;
    }

    {
        Editor_Message msg;
        msg.type = EDITOR_MESSAGE_JULIE_CLEAR;
        julie->get_editor_messages().push(msg);
        julie->request_pump();
    }

    *result = julie_nil_value(interp);

out:;
    return status;
});

#include "erlesys.h"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_sys.h>
#include <cstdint>

#include "util.h"

ESYS_CONTEXT *EsysContext = nullptr;

ERL_NIF_TERM Esys_EvictControl(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(EsysContext == nullptr)
        return Error(env, "no_context");

    ESYS_TR auth;
    enif_get_uint(env, argv[0], &auth);
    TPM2_HANDLE esys_handle;
    enif_get_uint(env, argv[1], &esys_handle);
    ESYS_TR shandle1;
    enif_get_uint(env, argv[2], &shandle1);
    ESYS_TR shandle2;
    enif_get_uint(env, argv[3], &shandle2);
    ESYS_TR shandle3;
    enif_get_uint(env, argv[4], &shandle3);
    ESYS_TR persistent_handle;
    enif_get_uint(env, argv[5], &persistent_handle);

    ESYS_TR new_handle;
    Esys_EvictControl(EsysContext, auth, esys_handle, shandle1, shandle2, shandle3, persistent_handle, &new_handle);

    return Success(env, enif_make_uint(env, new_handle));
}

ERL_NIF_TERM Esys_Finalize(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(EsysContext == nullptr)
        return Error(env, "no_context");

    Esys_Finalize(&EsysContext);

    return Success(env);
}

ERL_NIF_TERM Esys_GetCapability(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(EsysContext == nullptr)
        return Error(env, "no_context");

    ESYS_TR shandle1;
    enif_get_uint(env, argv[0], &shandle1);
    ESYS_TR shandle2;
    enif_get_uint(env, argv[1], &shandle2);
    ESYS_TR shandle3;
    enif_get_uint(env, argv[2], &shandle3);
    TPM2_CAP capability;
    enif_get_uint(env, argv[3], &capability);
    std::uint32_t property;
    enif_get_uint(env, argv[4], &property);
    std::uint32_t property_cnt;
    enif_get_uint(env, argv[5], &property_cnt);

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *cap_data;

    TSS2_RC result = Esys_GetCapability(EsysContext, shandle1, shandle2, shandle3, TPM2_CAP_HANDLES, TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES, &more_data, &cap_data);

    if(result != TSS2_RC_SUCCESS)
        return Error(env, result);

    std::vector<ERL_NIF_TERM> handles;

    for(int i = 0; i < cap_data->data.handles.count; ++i){
        handles.push_back(enif_make_uint(env, cap_data->data.handles.handle[i]));
    }

    return Success(env, handles, true);
}

ERL_NIF_TERM Esys_Initialize(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    TSS2_TCTI_CONTEXT *tcti_ctx;
    enif_get_uint64(env, argv[0], reinterpret_cast<std::uint64_t*>(&tcti_ctx));
    ESYS_CONTEXT *esys_ctx = nullptr;
    TSS2_RC result = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);

    if(result == TSS2_RC_SUCCESS) {
        EsysContext = esys_ctx;
        return Success(env);
    }
    else{
        return Error(env, result);
    }
}

ERL_NIF_TERM Esys_TR_FromTPMPublic(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(EsysContext == nullptr)
        return Error(env, "no_context");

    TPM2_HANDLE tpm2_handle;
    enif_get_uint(env, argv[0], &tpm2_handle);

    ESYS_TR shandle1;
    enif_get_uint(env, argv[1], &shandle1);

    ESYS_TR shandle2;
    enif_get_uint(env, argv[2], &shandle2);

    ESYS_TR shandle3;
    enif_get_uint(env, argv[3], &shandle3);

    ESYS_TR esys_handle;
    TSS2_RC result = Esys_TR_FromTPMPublic(
            EsysContext,
            tpm2_handle,
            shandle1,
            shandle2,
            shandle3,
            &esys_handle);

    if(result != TSS2_RC_SUCCESS)
        return Error(env, result);

    return Success(env, enif_make_uint(env, esys_handle));
}

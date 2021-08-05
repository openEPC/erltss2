#include "erlfapi.h"

#include <cstring>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_fapi.h>
#include <tss2/tss2_rc.h>

#include "util.h"

FAPI_CONTEXT *FapiContext = nullptr;

ERL_NIF_TERM Fapi_CreateKey(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    char* path = GetString(env, argv[0]);
    char* type = GetString(env, argv[1]);
    char* policy_path = GetString(env, argv[2]);
    char* auth = GetString(env, argv[3]);

    TSS2_RC result = Fapi_CreateKey(FapiContext, path, type, policy_path, auth);

    free(path);
    free(type);
    free(policy_path);
    free(auth);

    if(result == TSS2_RC_SUCCESS)
        return Success(env);
    else
        return Error(env, result);
}

ERL_NIF_TERM Fapi_Delete(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    char* path = GetString(env, argv[0]);

    TSS2_RC result = Fapi_Delete(FapiContext, path);

    free(path);

    if(result == TSS2_RC_SUCCESS)
        return Success(env);
    else
        return Error(env, result);
}

ERL_NIF_TERM Fapi_ECDHZGen(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    ESYS_CONTEXT *esys_ctx = nullptr;
    unsigned char *erl_secret_x = nullptr;
    unsigned char *erl_secret_y = nullptr;

    char* key_path = GetString(env, argv[0]);
    ErlNifBinary pub_point_x;
    int is_binary = enif_inspect_binary(env, argv[1], &pub_point_x);
    if(!is_binary)
        return Error(env, "x point is not binary");
    ErlNifBinary pub_point_y;
    is_binary = enif_inspect_binary(env, argv[2], &pub_point_y);
    if(!is_binary)
        return Error(env, "y point is not binary");

    if(pub_point_x.size > 128 || pub_point_y.size > 128)
        return Error(env, "key_too_long");

    TSS2_RC result;
    ESYS_TR esys_key_handle = -1;

    uint8_t type;
    uint8_t *esys_blob;
    size_t blob_sz;
    size_t offset = 0;
    result = Fapi_GetEsysBlob(FapiContext, key_path, &type, &esys_blob, &blob_sz);
    free(key_path);
    if(result != TSS2_RC_SUCCESS)
        goto error;

    if (type != FAPI_ESYSBLOB_CONTEXTLOAD)
        return Error(env, "wrong_key_path");

    TPMS_CONTEXT key_context;
    result = Tss2_MU_TPMS_CONTEXT_Unmarshal(esys_blob, blob_sz, &offset, &key_context);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    TSS2_TCTI_CONTEXT *tcti_ctx;
    result = Fapi_GetTcti(FapiContext, &tcti_ctx);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    result = Esys_Initialize(&esys_ctx, tcti_ctx, nullptr);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    result = Esys_ContextLoad(esys_ctx, &key_context, &esys_key_handle);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    TPM2B_ECC_POINT *secret;
    TPM2B_ECC_POINT pub_point;
    pub_point.point.x.size = pub_point_x.size;
    memcpy(pub_point.point.x.buffer, pub_point_x.data, pub_point_x.size);
    pub_point.point.y.size = pub_point_y.size;
    memcpy(pub_point.point.y.buffer, pub_point_y.data, pub_point_y.size);
    pub_point.size = pub_point.point.x.size + pub_point.point.y.size;

    result = Esys_ECDH_ZGen(esys_ctx, esys_key_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &pub_point, &secret);
    enif_release_binary(&pub_point_x);
    enif_release_binary(&pub_point_y);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    ERL_NIF_TERM secret_x_term;
    erl_secret_x = enif_make_new_binary(env, secret->point.x.size, &secret_x_term);
    memcpy(erl_secret_x, secret->point.x.buffer, secret->point.x.size);
    ERL_NIF_TERM secret_y_term;
    erl_secret_y = enif_make_new_binary(env, secret->point.y.size, &secret_y_term);
    memcpy(erl_secret_y, secret->point.y.buffer, secret->point.y.size);

    Esys_FlushContext(esys_ctx, esys_key_handle);
    Esys_Finalize(&esys_ctx);
    return Success(env, {secret_x_term, secret_y_term}, true);

    error:
    if(esys_key_handle != -1)
        Esys_FlushContext(esys_ctx, esys_key_handle);
    Esys_Finalize(&esys_ctx);
    return Error(env, result);
}

ERL_NIF_TERM Fapi_GetPublicKeyECC(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    ESYS_CONTEXT *esys_ctx = nullptr;
    unsigned char *erl_public_key = nullptr;
    TPMS_ECC_POINT *ecc_point = nullptr;

    char* key_path = GetString(env, argv[0]);

    TSS2_RC result;
    ESYS_TR esys_key_handle = -1;

    uint8_t type;
    uint8_t *esys_blob;
    size_t blob_sz;
    size_t offset = 0;
    result = Fapi_GetEsysBlob(FapiContext, key_path, &type, &esys_blob, &blob_sz);
    free(key_path);
    if(result != TSS2_RC_SUCCESS)
        goto error;

    if (type != FAPI_ESYSBLOB_CONTEXTLOAD)
        return Error(env, "wrong_key_path");


    TPMS_CONTEXT key_context;

    result = Tss2_MU_TPMS_CONTEXT_Unmarshal(esys_blob, blob_sz, &offset, &key_context);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    TSS2_TCTI_CONTEXT *tcti_ctx;
    result = Fapi_GetTcti(FapiContext, &tcti_ctx);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    result = Esys_Initialize(&esys_ctx, tcti_ctx, nullptr);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    result = Esys_ContextLoad(esys_ctx, &key_context, &esys_key_handle);
    if (result != TSS2_RC_SUCCESS)
        goto error;

    TPM2B_PUBLIC *public_part;
    TPM2B_NAME *public_name;
    TPM2B_NAME *qualif_name;
    Esys_ReadPublic(esys_ctx, esys_key_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &public_part, &public_name, &qualif_name);

    ecc_point = &public_part->publicArea.unique.ecc;

    ERL_NIF_TERM public_key_term;
    erl_public_key = enif_make_new_binary(env, ecc_point->x.size + ecc_point->y.size + 1, &public_key_term);
    erl_public_key[0] = 0x04;
    memcpy(erl_public_key + 1, ecc_point->x.buffer, ecc_point->x.size);
    memcpy(erl_public_key + ecc_point->x.size + 1, ecc_point->y.buffer, ecc_point->y.size);

    Esys_FlushContext(esys_ctx, esys_key_handle);
    Esys_Finalize(&esys_ctx);
    return Success(env, public_key_term);

    error:
    if(esys_key_handle != -1)
        Esys_FlushContext(esys_ctx, esys_key_handle);
    Esys_Finalize(&esys_ctx);
    return Error(env, result);
}

ERL_NIF_TERM Fapi_GetTcti(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    TSS2_TCTI_CONTEXT *tcti_ctx;
    TSS2_RC result = Fapi_GetTcti(FapiContext, &tcti_ctx);

    if(result != TSS2_RC_SUCCESS)
        return Error(env, result);

    return Success(env, enif_make_uint64(env, reinterpret_cast<std::uint64_t>(tcti_ctx)));
}

ERL_NIF_TERM Fapi_Initialize(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    char* uri = GetString(env, argv[0]);

    TSS2_RC result;
    FAPI_CONTEXT *fapi_ctx;
    result = Fapi_Initialize(&fapi_ctx, uri);
    free(uri);

    if(result == TSS2_RC_SUCCESS) {
        FapiContext = fapi_ctx;
        return Success(env);
    }
    else{
        return Error(env, result);
    }
}

ERL_NIF_TERM Fapi_Finalize(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    (void)argc;
    (void)argv;

    if(FapiContext == nullptr)
        return Error(env, "no_context");

    Fapi_Finalize(&FapiContext);
    FapiContext = nullptr;
    return Success(env);
}

ERL_NIF_TERM Fapi_List(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    char *path = GetString(env, argv[0]);
    char *pathList;

    TSS2_RC result = Fapi_List(FapiContext, path, &pathList);

    if(result != TSS2_RC_SUCCESS)
        return Error(env, result);

    ERL_NIF_TERM path_term = enif_make_string(env, pathList, ERL_NIF_LATIN1);
    delete[] pathList;

    return Success(env, path_term);
}

ERL_NIF_TERM Fapi_Provision(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    char* auth_e = GetString(env, argv[0]);
    char* auth_s = GetString(env, argv[1]);
    char* auth_lock = GetString(env, argv[2]);
    TSS2_RC result = Fapi_Provision(FapiContext, auth_e, auth_s, auth_lock);
    free(auth_e);
    free(auth_s);
    free(auth_lock);

    if(result == TSS2_RC_SUCCESS)
        return Success(env);
    else
        return Error(env, result);
}

ERL_NIF_TERM Fapi_RCDecode(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    TSS2_RC return_code;
    enif_get_uint(env, argv[0], &return_code);

    const char *decoded = Tss2_RC_Decode(return_code);
    return Success(env, enif_make_string(env, decoded, ERL_NIF_LATIN1));
}

ERL_NIF_TERM Fapi_Sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    TSS2_RC result;

    char* key_path = GetString(env, argv[0]);
    char* padding = GetString(env, argv[1]);
    ErlNifBinary digest;
    int is_binary = enif_inspect_binary(env, argv[2], &digest);
    if(!is_binary)
        return Error(env, "digest is not binary");
    uint8_t *signature;
    size_t signature_sz;
    char *public_key;
    char *certificate;
    result = Fapi_Sign(FapiContext, key_path, padding, digest.data, digest.size, &signature, &signature_sz, &public_key, &certificate);
    free(key_path);
    free(padding);

    enif_release_binary(&digest);
    ERL_NIF_TERM signature_term;
    unsigned char *erl_signature = enif_make_new_binary(env, signature_sz, &signature_term);
    memcpy(erl_signature, signature, signature_sz);
    free(signature);

    ERL_NIF_TERM public_key_term = enif_make_string(env, public_key, ERL_NIF_LATIN1);
    free(public_key);
    ERL_NIF_TERM certificate_term = enif_make_string(env, certificate, ERL_NIF_LATIN1);
    free(certificate);
    if(result == TSS2_RC_SUCCESS)
        return Success(env, {signature_term, public_key_term, certificate_term}, false);
    else
        return Error(env, result);
}

ERL_NIF_TERM Fapi_VerifySignature(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    if(FapiContext == nullptr)
        return Error(env, "no_context");

    TSS2_RC result;
    char* key_path = GetString(env, argv[0]);
    ErlNifBinary digest;
    int is_binary = enif_inspect_binary(env, argv[1], &digest);
    if(!is_binary)
        return Error(env, "digest is not binary");
    ErlNifBinary signature;
    is_binary = enif_inspect_binary(env, argv[2], &signature);
    if(!is_binary)
        return Error(env, "signature is not binary");

    result = Fapi_VerifySignature(FapiContext, key_path, digest.data, digest.size, signature.data, signature.size);

    free(key_path);

    if(result == TSS2_RC_SUCCESS)
        return Success(env);
    else
        return Error(env, result);
}

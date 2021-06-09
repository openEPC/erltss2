#include "erlfapi.h"

#include <string.h>

#include <tss2/tss2_mu.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_fapi.h>

#include "util.h"

FAPI_CONTEXT *FapiContext = NULL;

ERL_NIF_TERM NFapi_Initialize(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 1)
        return enif_make_atom(env, "too_few_args");

    char* uri = GetString(env, argv[0]);

    TSS2_RC result;
    FAPI_CONTEXT *fapi_ctx;
    result = Fapi_Initialize(&fapi_ctx, uri);
    free(uri);

    if(result == TSS2_RC_SUCCESS)
        FapiContext = fapi_ctx;

    return enif_make_uint(env, result);
}

ERL_NIF_TERM NFapi_Finalize(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    (void)argc;
    (void)argv;

    if(FapiContext != NULL) {
        Fapi_Finalize(&FapiContext);
        FapiContext = NULL;
        return enif_make_uint(env, TSS2_RC_SUCCESS);
    }
    else
        return enif_make_atom(env, "no_context");
}

ERL_NIF_TERM NFapi_Provision(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 3)
        return enif_make_atom(env, "too_few_args");

    if(FapiContext == NULL)
        return enif_make_atom(env, "no_context");

    char* auth_e = GetString(env, argv[0]);
    char* auth_s = GetString(env, argv[1]);
    char* auth_lock = GetString(env, argv[2]);
    TSS2_RC result = Fapi_Provision(FapiContext, auth_e, auth_s, auth_lock);
    free(auth_e);
    free(auth_s);
    free(auth_lock);

    return enif_make_uint(env, result);
}

ERL_NIF_TERM NFapi_CreateKey(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 4)
        return enif_make_atom(env, "too_few_args");

    if(FapiContext == NULL)
        return enif_make_atom(env, "no_context");

    char* path = GetString(env, argv[0]);
    char* type = GetString(env, argv[1]);
    char* policy_path = GetString(env, argv[2]);
    char* auth = GetString(env, argv[3]);

    TSS2_RC result = Fapi_CreateKey(FapiContext, path, type, policy_path, auth);

    free(path);
    free(type);
    free(policy_path);
    free(auth);

    return enif_make_uint(env, result);
}

ERL_NIF_TERM NFapi_Sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 3)
        return enif_make_atom(env, "too_few_args");

    if(FapiContext == NULL)
        return enif_make_atom(env, "no_context");

    TSS2_RC result;

    char* key_path = GetString(env, argv[0]);
    char* padding = GetString(env, argv[1]);
    ErlNifBinary digest;
    enif_term_to_binary(env, argv[2], &digest);
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
    return enif_make_tuple(env, 4,
                           enif_make_uint(env, result),
                           signature_term,
                           public_key_term,
                           certificate_term);
}

ERL_NIF_TERM NFapi_VerifySignature(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 5)
        return enif_make_atom(env, "too_few_args");

    if(FapiContext == NULL)
        return enif_make_atom(env, "no_context");

    TSS2_RC result;
    char* key_path = GetString(env, argv[0]);
    ErlNifBinary digest;
    enif_term_to_binary(env, argv[2], &digest);
    ErlNifBinary signature;
    enif_term_to_binary(env, argv[3], &signature);

    result = Fapi_VerifySignature(FapiContext, key_path, digest.data, digest.size, signature.data, signature.size);

    free(key_path);

    return enif_make_uint(env, result);
}

ERL_NIF_TERM NFAPI_ECDHZGen(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 3)
        return enif_make_atom(env, "too_few_args");

    if(FapiContext == NULL)
        return enif_make_atom(env, "no_context");

    char* key_path = GetString(env, argv[0]);
    ErlNifBinary pub_point_x;
    enif_term_to_binary(env, argv[1], &pub_point_x);
    ErlNifBinary pub_point_y;
    enif_term_to_binary(env, argv[2], &pub_point_y);

    if(pub_point_x.size > 128 || pub_point_y.size > 128)
        return enif_make_atom(env, "key_too_long");

    TSS2_RC r;

    uint8_t type;
    uint8_t *esys_blob;
    size_t blob_sz;
    r = Fapi_GetEsysBlob(FapiContext, key_path, &type, &esys_blob, &blob_sz);
    free(key_path);
    if(r != TSS2_RC_SUCCESS)
        goto error;

    if (type != FAPI_ESYSBLOB_CONTEXTLOAD) {
        return enif_make_atom(env, "wrong_key_path");
    }

    TPMS_CONTEXT key_context;
    size_t offset = 0;
    r = Tss2_MU_TPMS_CONTEXT_Unmarshal(esys_blob, blob_sz, &offset, &key_context);
    if (r != TSS2_RC_SUCCESS)
        goto error;

    ESYS_CONTEXT *esys_ctx;
    TSS2_TCTI_CONTEXT *tcti_ctx;
    r = Fapi_GetTcti(FapiContext, &tcti_ctx);
    if (r != TSS2_RC_SUCCESS)
        goto error;

    r = Esys_Initialize(&esys_ctx, tcti_ctx, NULL);
    if (r != TSS2_RC_SUCCESS)
        goto error;

    ESYS_TR esys_key_handle;
    r = Esys_ContextLoad(esys_ctx, &key_context, &esys_key_handle);
    if (r != TSS2_RC_SUCCESS)
        goto error;

    TPM2B_ECC_POINT *secret;
    TPM2B_ECC_POINT pub_point;
    pub_point.point.x.size = pub_point_x.size;
    memcpy(pub_point.point.x.buffer, pub_point_x.data, pub_point_x.size);
    pub_point.point.y.size = pub_point_y.size;
    memcpy(pub_point.point.y.buffer, pub_point_y.data, pub_point_y.size);
    pub_point.size = pub_point.point.x.size + pub_point.point.y.size;

    r = Esys_ECDH_ZGen(esys_ctx, esys_key_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &pub_point, &secret);
    enif_release_binary(&pub_point_x);
    enif_release_binary(&pub_point_y);
    if (r != TSS2_RC_SUCCESS)
        goto error;

    ERL_NIF_TERM secret_x_term;
    unsigned char *erl_secret_x = enif_make_new_binary(env, secret->point.x.size, &secret_x_term);
    memcpy(erl_secret_x, secret->point.x.buffer, secret->point.x.size);
    ERL_NIF_TERM secret_y_term;
    unsigned char *erl_secret_y = enif_make_new_binary(env, secret->point.y.size, &secret_y_term);
    memcpy(erl_secret_y, secret->point.y.buffer, secret->point.y.size);

    return enif_make_tuple(env, 2, secret_x_term, secret_y_term);

error:
    return enif_make_uint(env, r);
}


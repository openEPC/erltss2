#include "erlfapi.h"

#include <cstring>

#include <tss2/tss2_fapi.h>

#include "util.h"

std::unordered_map<ErlNifEnv*, FAPI_CONTEXT*> ContextStorage;

ERL_NIF_TERM Fapi_Initialize(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 1)
        return enif_make_atom(env, "too_few_args");

    auto uri = NifUtils::GetString(env, argv[0]);

    TSS2_RC result;
    FAPI_CONTEXT *fapi_ctx;
    result = Fapi_Initialize(&fapi_ctx, uri.get());

    if(result == TSS2_RC_SUCCESS)
        ContextStorage[env] = fapi_ctx;

    return enif_make_uint(env, result);
}

ERL_NIF_TERM Fapi_Finalize(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    (void)argc;
    (void)argv;
    auto ctx = ContextStorage.find(env);

    if(ctx != ContextStorage.end()) {
        Fapi_Finalize(&ctx->second);
        return enif_make_uint(env, TSS2_RC_SUCCESS);
    }
    else
        return enif_make_atom(env, "no_context");
}

ERL_NIF_TERM Fapi_Provision(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 3)
        return enif_make_atom(env, "too_few_args");

    auto ctx = ContextStorage.find(env);

    if(ctx != ContextStorage.end()) {
        TSS2_RC result;

        auto auth_e = NifUtils::GetString(env, argv[0]);
        auto auth_s = NifUtils::GetString(env, argv[1]);
        auto auth_lock = NifUtils::GetString(env, argv[2]);
        result = Fapi_Provision(ctx->second, auth_e.get(), auth_s.get(), auth_lock.get());
        return enif_make_uint(env, result);
    }
    else
        return enif_make_atom(env, "no_context");
}

ERL_NIF_TERM Fapi_CreateKey(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 4)
        return enif_make_atom(env, "too_few_args");

    auto ctx = ContextStorage.find(env);

    if(ctx != ContextStorage.end()) {
        TSS2_RC result;

        auto path = NifUtils::GetString(env, argv[0]);
        auto type = NifUtils::GetString(env, argv[1]);
        auto policy_path = NifUtils::GetString(env, argv[2]);
        auto auth = NifUtils::GetString(env, argv[3]);
        result = Fapi_CreateKey(ctx->second, path.get(), type.get(), policy_path.get(), auth.get());
        return enif_make_uint(env, result);
    }
    else
        return enif_make_atom(env, "no_context");
}

ERL_NIF_TERM Fapi_Sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 5)
        return enif_make_atom(env, "too_few_args");

    auto ctx = ContextStorage.find(env);

    if(ctx != ContextStorage.end()) {
        TSS2_RC result;

        auto key_path = NifUtils::GetString(env, argv[0]);
        auto padding = NifUtils::GetString(env, argv[1]);
        ErlNifBinary digest;
        enif_term_to_binary(env, argv[2], &digest);
        auto policy_path = NifUtils::GetString(env, argv[3]);
        auto auth = NifUtils::GetString(env, argv[4]);
        std::uint8_t *signature;
        std::size_t signature_sz;
        char *public_key;
        char *certificate;
        result = Fapi_Sign(ctx->second, key_path.get(), padding.get(), digest.data, digest.size, &signature, &signature_sz, &public_key, &certificate);

        enif_release_binary(&digest);
        ERL_NIF_TERM signature_term;
        unsigned char *erl_signature = enif_make_new_binary(env, signature_sz, &signature_term);
        memcpy(erl_signature, signature, signature_sz);
        delete[] signature;

        auto public_key_term = enif_make_string(env, public_key, ERL_NIF_LATIN1);
        delete[] public_key;
        auto certificate_term = enif_make_string(env, certificate, ERL_NIF_LATIN1);
        delete[] certificate;
        return enif_make_tuple(env, 4,
                               enif_make_uint(env, result),
                               signature_term,
                               public_key_term,
                               certificate_term);
    }
    else
        return enif_make_atom(env, "no_context");
}

ERL_NIF_TERM Fapi_VerifySignature(ErlNifEnv *env, int argc, const ERL_NIF_TERM *argv) {
    if(argc < 5)
        return enif_make_atom(env, "too_few_args");

    auto ctx = ContextStorage.find(env);

    if(ctx != ContextStorage.end()) {
        TSS2_RC result;
        auto key_path = NifUtils::GetString(env, argv[0]);
        ErlNifBinary digest;
        enif_term_to_binary(env, argv[2], &digest);
        ErlNifBinary signature;
        enif_term_to_binary(env, argv[3], &signature);

        result = Fapi_VerifySignature(ctx->second, key_path.get(), digest.data, digest.size, signature.data, signature.size);

        return enif_make_uint(env, result);
    }
    else
        return enif_make_atom(env, "no_context");
}

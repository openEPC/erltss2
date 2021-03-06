#pragma once

#include <erl_nif.h>

static ERL_NIF_TERM Fapi_CreateKey(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_Delete(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_ECDHZGen(ErlNifEnv* env, int argc, const ERL_NIF_TERM *argv);

static ERL_NIF_TERM Fapi_Finalize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_GetPublicKeyECC(ErlNifEnv* env, int argc, const ERL_NIF_TERM *argv);

static ERL_NIF_TERM Fapi_GetTcti(ErlNifEnv* env, int argc, const ERL_NIF_TERM *argv);

static ERL_NIF_TERM Fapi_Initialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_List(ErlNifEnv* env, int argc, const ERL_NIF_TERM *argv);

static ERL_NIF_TERM Fapi_Provision(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_RCDecode(ErlNifEnv* env, int argc, const ERL_NIF_TERM *argv);

static ERL_NIF_TERM Fapi_Sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_VerifySignature(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ErlNifFunc nif_funcs[] = {
        {"create_key",          4, Fapi_CreateKey},
        {"delete",              1, Fapi_Delete},
        {"ecdh_zgen",           3, Fapi_ECDHZGen},
        {"finalize",            0, Fapi_Finalize},
        {"get_public_key_ecc",  1, Fapi_GetPublicKeyECC},
        {"get_tcti",            0, Fapi_GetTcti},
        {"initialize",          1, Fapi_Initialize},
        {"list",                1, Fapi_List},
        {"provision",           3, Fapi_Provision},
        {"rc_decode",           1, Fapi_RCDecode},
        {"sign",                3, Fapi_Sign},
        {"verify_signature",    3, Fapi_VerifySignature}
};

ERL_NIF_INIT(erlfapi, nif_funcs, NULL, NULL, NULL, NULL)
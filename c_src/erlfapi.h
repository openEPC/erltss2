#pragma once

#include <erl_nif.h>

static ERL_NIF_TERM NFapi_Initialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM NFapi_Finalize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM NFapi_Provision(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM NFapi_CreateKey(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM NFapi_Sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM NFapi_VerifySignature(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM NFAPI_ECDHZGen(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM NFAPI_GetPublicKeyECC(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ErlNifFunc nif_funcs[] = {
        {"fapi_Initialize", 1, NFapi_Initialize},
        {"fapi_Finalize", 0, NFapi_Finalize},
        {"fapi_Provision", 3, NFapi_Provision},
        {"fapi_CreateKey", 4, NFapi_CreateKey},
        {"fapi_Sign", 3, NFapi_Sign},
        {"fapi_VerifySignature", 5, NFapi_VerifySignature},
        {"fapi_EDCHZGen", 3, NFAPI_ECDHZGen},
        {"fapi_GetPublicKeyECC", 1, NFAPI_GetPublicKeyECC}
};

ERL_NIF_INIT(erlfapi, nif_funcs, NULL, NULL, NULL, NULL)
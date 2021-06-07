#pragma once

#include <erl_nif.h>
#include <unordered_map>

static ERL_NIF_TERM Fapi_Initialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_Finalize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_Provision(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_CreateKey(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_Sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Fapi_VerifySignature(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ErlNifFunc nif_funcs[] = {
        {"fapi_Initialize", 1, Fapi_Initialize},
        {"fapi_Finalize", 0, Fapi_Finalize},
        {"fapi_Provision", 3, Fapi_Provision},
        {"fapi_CreateKey", 4, Fapi_CreateKey},
        {"fapi_Sign", 5, Fapi_Sign},
        {"fapi_VerifySignature", 5, Fapi_VerifySignature}
};

ERL_NIF_INIT(erlfapi, nif_funcs, NULL, NULL, NULL, NULL)
#pragma once

#include <erl_nif.h>

static ERL_NIF_TERM Esys_Initialize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Esys_TR_FromTPMPublic(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Esys_Finalize(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Esys_EvictControl(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ERL_NIF_TERM Esys_GetCapability(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);

static ErlNifFunc nif_funcs[] = {
        {"initialize", 1,    Esys_Initialize},
        {"finalize", 0,      Esys_Finalize},
        {"get_capability", 6, Esys_GetCapability},
        {"evict_control", 6,  Esys_EvictControl},
        {"tr_from_tpm_public", 4, Esys_TR_FromTPMPublic}
};

ERL_NIF_INIT(erlesys, nif_funcs, NULL, NULL, NULL, NULL)
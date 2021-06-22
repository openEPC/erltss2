#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <erl_nif.h>


char* GetString(ErlNifEnv *env, ERL_NIF_TERM term);

ERL_NIF_TERM Success(ErlNifEnv *env);

ERL_NIF_TERM Success(ErlNifEnv *env, std::vector<ERL_NIF_TERM> terms);

template <typename T>
ERL_NIF_TERM Error(ErlNifEnv *env, T val);

template <>
ERL_NIF_TERM Error<std::uint32_t>(ErlNifEnv *env, std::uint32_t val);

template <>
ERL_NIF_TERM Error<const char*>(ErlNifEnv *env, const char *val);

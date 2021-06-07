#pragma once

#include <erl_nif.h>
#include <memory>

namespace NifUtils {
    std::unique_ptr<char> GetString(ErlNifEnv *env, ERL_NIF_TERM term);
}
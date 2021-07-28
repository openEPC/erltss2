#include <vector>
#include "util.h"

char* GetString(ErlNifEnv *env, const ERL_NIF_TERM term) {
    unsigned int buf_sz = 100;
    char* buf = nullptr;
    while(!buf) {
        buf = new char[buf_sz];
        int written = enif_get_string(env, term, buf, buf_sz, ERL_NIF_LATIN1);
        if(written <= 0) {
            delete[] buf;
            buf = nullptr;

            if (written == 0)   // NULL
                break;
            else                // truncated
                buf_sz *= 2;
        }
    }

    return buf;
}

ERL_NIF_TERM Success(ErlNifEnv *env) {
    return enif_make_atom(env, "ok");
}

ERL_NIF_TERM Success(ErlNifEnv *env, ERL_NIF_TERM term) {
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), term);
}

ERL_NIF_TERM Success(ErlNifEnv *env, std::vector<ERL_NIF_TERM> terms, bool homegeneous) {
    if(homegeneous)
        return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_list_from_array(env, terms.data(), terms.size()));
    else
        return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_tuple_from_array(env, terms.data(), terms.size()));
}

template<>
ERL_NIF_TERM Error<std::uint32_t>(ErlNifEnv *env, uint32_t val) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_uint(env, val));
}

template<>
ERL_NIF_TERM Error<const char*>(ErlNifEnv *env, const char *val) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, val));
}







#include "util.h"

char* GetString(ErlNifEnv *env, const ERL_NIF_TERM term) {
    unsigned int buf_sz = 100;
    char* buf = NULL;
    while(!buf) {
        buf = malloc(buf_sz * sizeof(char));
        int written = enif_get_string(env, term, buf, buf_sz, ERL_NIF_LATIN1);
        if(written <= 0) {
            free(buf);
            buf = NULL;

            if (written == 0)   // NULL
                break;
            else                // truncated
                buf_sz *= 2;
        }
    }

    return buf;
}

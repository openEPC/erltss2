#include "util.h"

namespace NifUtils {

    std::unique_ptr<char> GetString(ErlNifEnv *env, const ERL_NIF_TERM term) {
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

        return std::unique_ptr<char>(buf);
    }

}

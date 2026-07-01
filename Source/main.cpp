#include <iostream>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include "argon2.h"

int main() {
    const char *pwd = "password";
    const uint8_t salt[] = "somesalt";
    uint8_t hash[32];
    int ret = argon2id_hash_raw(
        /*t_cost=*/2,
        /*m_cost=*/1<<16,
        /*parallelism=*/1,
        pwd, std::strlen(pwd),
        salt, sizeof(salt)-1,
        hash, sizeof(hash)
    );
    if (ret != ARGON2_OK) {
        std::cerr << argon2_error_message(ret) << std::endl;
        return 1;
    }
    for (size_t i = 0; i < sizeof(hash); ++i) printf("%02x", hash[i]);
    printf("\n");
    return 0;
}

/*
 * functionbin — ShopStack custom SUID utility (HARD revision).
 *
 * The only supported operation is `functionbin -x <path>`, which prints <path> to
 * stdout. It is installed root-owned and SUID (mode 4755), so the read happens with
 * EUID 0.
 *
 * Non-announcing: wrong/absent arguments fail SILENTLY with a generic non-zero exit
 * and NO usage text. The `-x` token still lives in the binary and is recoverable via
 * `strings functionbin`.
 *
 * INTENTIONALLY VULNERABLE: SUID-root binary performs an arbitrary file read as root
 * and never drops privileges before fopen(). Intended Stage 3 privesc primitive.
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "-x") == 0) {
        /* Does NOT drop privileges; opens argv[2] while EUID == 0. */
        FILE *f = fopen(argv[2], "r");
        if (!f) {
            return 1;
        }
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
            fwrite(buf, 1, n, stdout);
        }
        fclose(f);
        return 0;
    }

    /* Silent, generic failure: no usage string, no hint about -x. */
    return 1;
}

/*
 * functionbin — ShopStack SUID utility. Only op: `functionbin -x <path>` prints the
 * file to stdout. Installed SUID root (4755); non-announcing (no usage text, silent
 * failure). INTENTIONALLY VULNERABLE: arbitrary file read as root, no privilege drop.
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "-x") == 0) {
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

    return 1;
}

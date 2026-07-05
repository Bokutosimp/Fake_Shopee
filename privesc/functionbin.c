/*
 * functionbin — ShopStack custom SUID utility.
 *
 * "One function that works, the rest fail." The only supported operation is
 *   functionbin -x <path>
 * which prints <path> to stdout. Because the binary is installed root-owned and
 * SUID (mode 4755), the read happens with EUID 0.
 *
 * INTENTIONALLY VULNERABLE: SUID-root binary performs an arbitrary file read as
 * root and never drops privileges before fopen(). This is the intended Stage 3
 * privesc primitive (arbitrary root read of /root/root.txt), not a full shell.
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "-x") == 0) {
        /* Does NOT drop privileges; opens argv[2] while EUID == 0. */
        FILE *f = fopen(argv[2], "r");
        if (!f) {
            perror("functionbin");
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

    fprintf(stderr, "usage: functionbin -x <path>\n");
    return 2;
}

#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>

#include "elfdefinitions.h"
#include "lfiv.h"
#include "args.h"

static struct LFIVOptions opts;

#ifndef SHT_ANDROID_RELR
#define SHT_ANDROID_RELR 0x6fffff00
#endif

static char *
archname(const char *s)
{
#ifdef ARCH_X64
    if (strcmp(s, "amd64") == 0 || strcmp(s, "x64") == 0 || strcmp(s, "x86_64") == 0)
        return "x64";
#endif
#ifdef ARCH_ARM64
    if (strcmp(s, "arm64") == 0 || strcmp(s, "aarch64") == 0)
        return "arm64";
#endif
    return NULL;
}

static inline
long long unsigned time_ns()
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts)) {
        exit(1);
    }
    return ((long long unsigned)ts.tv_sec) * 1000000000LLU +
        (long long unsigned)ts.tv_nsec;
}

static bool
verify(struct LFIVerifier *v, const char *filename)
{
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "failed to open %s: %s\n", filename, strerror(errno));
        return false;
    }

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), file) != sizeof(ehdr)) {
        fprintf(stderr, "failed to read ELF header: %s\n", strerror(errno));
        goto err;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "not a valid 64-bit ELF file\n");
        goto err;
    }

    switch (ehdr.e_machine) {
    case EM_X86_64:
#ifdef ARCH_X64
        if (!args.arch || strcmp(args.arch, "x64") == 0) {
            v->verify = lfiv_verify_x64;
            break;
        }
#endif
        fprintf(stderr, "error: ELF file is x64, not %s\n", args.arch);
        goto err;
    case EM_AARCH64:
#ifdef ARCH_ARM64
        if (!args.arch || strcmp(args.arch, "arm64") == 0) {
            v->verify = lfiv_verify_arm64;
            break;
        }
#endif
        fprintf(stderr, "error: ELF file is arm64, not %s\n", args.arch);
        goto err;
    default:
        fprintf(stderr, "ELF architecture is not x64 or arm64\n");
        goto err;
    }

    for (int i = 0; i < ehdr.e_shnum; ++i) {
        if (fseek(file, ehdr.e_shoff + i * sizeof(Elf64_Shdr), SEEK_SET) != 0) {
            fprintf(stderr, "seek failed: %s\n", strerror(errno));
            goto err;
        }

        Elf64_Shdr shdr;
        if (fread(&shdr, 1, sizeof(shdr), file) != sizeof(shdr)) {
            fprintf(stderr, "read failed: %s\n", strerror(errno));
            goto err;
        }

        if (shdr.sh_type == SHT_ANDROID_RELR) {
            fprintf(stderr, "error: SHT_ANDROID_RELR section is not supported\n");
            goto err;
        }
    }

    assert(v->verify != NULL);

    size_t total = 0;

    long long unsigned t1 = time_ns();
    for (int n = 0; n < args.n; n++) {
        for (int i = 0; i < ehdr.e_phnum; ++i) {
            if (fseek(file, ehdr.e_phoff + i * sizeof(Elf64_Phdr), SEEK_SET) != 0) {
                fprintf(stderr, "seek failed: %s\n", strerror(errno));
                goto err;
            }

            Elf64_Phdr phdr;
            if (fread(&phdr, 1, sizeof(phdr), file) != sizeof(phdr)) {
                fprintf(stderr, "read failed: %s\n", strerror(errno));
                goto err;
            }

            if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
                void *segment = malloc(phdr.p_filesz);
                if (!segment) {
                    fprintf(stderr, "error: out of memory\n");
                    goto err;
                }

                if (fseek(file, phdr.p_offset, SEEK_SET) != 0) {
                    fprintf(stderr, "seek failed: %s\n", strerror(errno));
                    free(segment);
                    goto err;
                }

                if (fread(segment, 1, phdr.p_filesz, file) != phdr.p_filesz) {
                    fprintf(stderr, "read failed: %s\n", strerror(errno));
                    free(segment);
                    goto err;
                }

                if (!lfiv_verify(v, segment, phdr.p_filesz, phdr.p_vaddr)) {
                    fprintf(stderr, "verification failed\n");
                    return false;
                }

                total += phdr.p_filesz;

                free(segment);
            }
        }
    }
    long long unsigned elapsed = time_ns() - t1;

    fclose(file);
    printf("verification passed (%.1f MiB/s)\n", ((float) total / ((float) elapsed / 1000 / 1000 / 1000)) / 1024 / 1024);
    return true;
err:
    fclose(file);
    return false;
}

struct Args args;

static void
showerr(char *msg, size_t sz)
{
    (void) sz;
    fprintf(stderr, "%s\n", msg);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [OPTION...] INPUT...\n\n"
            "  -h, --help              show help\n"
            "  -a, --arch=ARCH         run on architecture (x64,arm64)\n"
            "  -n, --n=NUM             run the verifier n times (for benchmarking)\n"
            "  -s, --sandbox=TYPE      select sandbox type (full,stores)\n"
            "      --no-bdd            disable the BDD filter (x86-64)\n"
            , prog);
    exit(1);
}

int
main(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"arch", required_argument, 0, 'a'},
        {"n", required_argument, 0, 'n'},
        {"sandbox", required_argument, 0, 's'},
        {"no-bdd", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    args.n = 1;

    while ((opt = getopt_long(argc, argv, "ha:n:s:", long_options, &long_index)) != -1) {
        switch (opt) {
        case 'h':
            usage(argv[0]);
            break;
        case 'a':
            args.arch = archname(optarg);
            if (!args.arch) {
                fprintf(stderr, "unknown architecture: %s\n", optarg);
                return 1;
            }
            break;
        case 'n':
            args.n = atoi(optarg);
            break;
        case 's':
            if (strcmp(optarg, "full") == 0)
                opts.box = LFI_BOX_FULL;
            else if (strcmp(optarg, "stores") == 0)
                opts.box = LFI_BOX_STORES;
            else {
                fprintf(stderr, "unsupported sandbox type: %s\n", optarg);
                return 1;
            }
            break;
        case 0:
            if (strcmp(long_options[long_index].name, "no-bdd") == 0) {
                opts.no_bdd = true;
            }
            break;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
    }

    for (int i = optind; i < argc; i++) {
        if (args.ninputs >= INPUTMAX) {
            fprintf(stderr, "too many input files\n");
            return 1;
        }
        args.inputs[args.ninputs++] = argv[i];
    }

    opts.err = showerr;
    struct LFIVerifier v = (struct LFIVerifier) {
        .opts = opts,
    };

    bool failed = false;
    for (size_t i = 0; i < args.ninputs; i++) {
        if (!verify(&v, args.inputs[i]))
            failed = true;
    }
    if (failed)
        return 1;

    return 0;
}

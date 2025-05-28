#include <assert.h>
#include <argp.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <elf.h>

#include "lfiv.h"
#include "args.h"

static char doc[] = "lfiv: LFI verifier";

static char args_doc[] = "INPUT...";

static struct argp_option options[] = {
    { "help",           'h',               0,      0, "show this message", -1 },
    { "arch",           'a',               "ARCH", 0, "run on architecture (x64,arm64)" },
    { "n",              'n',               "NUM",  0, "run the verifier n times (for benchmarking)" },
    { "sandbox",        's',               "TYPE", 0, "Select sandbox type (full,stores)" },
    { 0 },
};

static struct LFIVOptions opts;

static char *
archname(char *s)
{
#ifdef ARCH_X64
    if (strcmp(s, "amd64") == 0 || strcmp(s, "x64") == 0 || strcmp(s, "x86_64") == 0)
        return "x64";
#endif
#ifdef ARCH_ARM64
    if (strcmp(s, "arm64") == 0 || strcmp(s, "aarch64") == 0)
        return "arm64";
#endif
    return "unknown";
}

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    struct Args *args = state->input;

    char *arch;
    switch (key) {
    case 'h':
        argp_state_help(state, state->out_stream, ARGP_HELP_STD_HELP);
        break;
    case 'n':
        args->n = atoi(arg);
        break;
    case 'a':
        arch = archname(arg);
        if (strcmp(arch, "x64") != 0 &&
            strcmp(arch, "arm64") != 0) {
            fprintf(stderr, "unknown architecture: %s\n", arg);
            return ARGP_ERR_UNKNOWN;
        }
        args->arch = arch;
        break;
    case 's':
        if (strcmp(arg, "full") == 0)
            opts.box = LFI_BOX_FULL;
        else if (strcmp(arg, "stores") == 0)
            opts.box = LFI_BOX_STORES;
        else {
            fprintf(stderr, "unsupported sandbox type: %s\n", arg);
            return ARGP_ERR_UNKNOWN;
        }
        break;
    case ARGP_KEY_ARG:
        if (args->ninputs < INPUTMAX)
            args->inputs[args->ninputs++] = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc };

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

    assert(v->verify != NULL);

    size_t total = 0;

    long long unsigned t1 = time_ns();
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

int
main(int argc, char **argv)
{
    argp_parse(&argp, argc, argv, ARGP_NO_HELP, 0, &args);

    if (args.n == 0)
        args.n = 1;

    opts.err = showerr;
    struct LFIVerifier v = (struct LFIVerifier) {
        .opts = opts,
    };

    if (args.ninputs <= 0) {
        fprintf(stderr, "no input\n");
        return 0;
    }

    bool failed = false;
    for (size_t i = 0; i < args.ninputs; i++) {
        if (!verify(&v, args.inputs[i]))
            failed = true;
    }
    if (failed)
        return 1;

    return 0;
}

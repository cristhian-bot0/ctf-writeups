// Proofmark - HTB Cyber Apocalypse 2026 (mobile)
//
// Manually maps the Android x86_64 GDExtension (libproofmark.x86_64.so) into this
// process and calls its two internal routines directly, bypassing Godot entirely:
//
//   0x1c10  uint32_t assay_vm(const void *state16, size_t len)
//               runs the embedded bytecode VM over the 16-byte ring state and
//               returns register r0 -- but only if the state passes the
//               "stress path" validator (w_i <= 24 and bite == w0+2*w1+3*w2);
//               otherwise it returns a scrambled value.
//
//   0x20d0  int  certify(const void *mark16, size_t len, uint32_t hallmark,
//                        char *out, int outlen)
//               0 = REJECT_STATE (mark != the Signet's own 16 bytes)
//               1 = REJECT_TOKEN (hallmark wrong -> plaintext isn't a flag)
//               2 = ACCEPTED     (out = certificate)
//
// Run with -p to also patch out the validator inside the VM so it returns r0 for
// the (illegal) target state -- that value is the forged proofmark.
//
// build: cc -O2 -o harness harness.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#define MAPSZ 0x6000

/* offsets inside the .so */
#define OFF_VM      0x1c10
#define OFF_CERT    0x20d0
#define OFF_GOT_MEMCPY 0x40b8
#define OFF_TARGET_MARK 0x530
#define OFF_VALIDATOR 0x2054   /* cmp esi,0x10 ... -> jmp epilogue */
#define OFF_EPILOGUE  0x20b0

typedef uint32_t (*vm_fn)(const void *, uint64_t);
typedef int (*cert_fn)(const void *, uint64_t, uint32_t, char *, int);

/* PT_LOAD segments: offset, vaddr, filesz */
static const struct { long off, vaddr, filesz; } segs[] = {
    {0x000000, 0x0000, 0x0b94},
    {0x000ba0, 0x1ba0, 0x1360},
    {0x001f00, 0x3f00, 0x01c0},
};

int main(int argc, char **argv) {
    int patch = (argc > 2 && strcmp(argv[2], "-p") == 0);
    const char *path = argc > 1 ? argv[1]
                                : "extracted/lib/x86_64/libproofmark.x86_64.so";

    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    static unsigned char file[0x4000];
    size_t n = fread(file, 1, sizeof file, f);
    fclose(f);
    printf("[*] %s (%zu bytes)\n", path, n);

    unsigned char *base = mmap(NULL, MAPSZ, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); return 1; }

    for (unsigned i = 0; i < sizeof segs / sizeof segs[0]; i++)
        memcpy(base + segs[i].vaddr, file + segs[i].off, segs[i].filesz);

    /* only relocation that matters for the routines we call */
    *(void **)(base + OFF_GOT_MEMCPY) = (void *)memcpy;

    if (patch) {
        /* replace "cmp esi,0x10 / jne garble" with an unconditional jump to the
           epilogue, so the VM returns r0 even for an invalid ring state */
        base[OFF_VALIDATOR]     = 0xeb;                                /* jmp rel8 */
        base[OFF_VALIDATOR + 1] = (unsigned char)(OFF_EPILOGUE - (OFF_VALIDATOR + 2));
        printf("[*] validator patched out (VM returns r0 unconditionally)\n");
    }

    vm_fn assay = (vm_fn)(base + OFF_VM);
    cert_fn certify = (cert_fn)(base + OFF_CERT);

    /* the 16 bytes the anvil demands: the Signet's own ring geometry */
    unsigned char mark[16];
    memcpy(mark, base + OFF_TARGET_MARK, 16);
    int32_t *w = (int32_t *)mark;
    printf("[*] target mark : wards %d / %d / %d   bite %d\n", w[0], w[1], w[2], w[3]);
    printf("[*] stress path : %d + 2*%d + 3*%d = %d  (declared bite %d -> %s)\n",
           w[0], w[1], w[2], w[0] + 2 * w[1] + 3 * w[2], w[3],
           (w[0] + 2 * w[1] + 3 * w[2] == w[3]) ? "valid" : "INVALID");

    uint32_t hallmark = assay(mark, 16);
    printf("[*] hallmark    : 0x%08x (%u)\n", hallmark, hallmark);

    char out[0x100];
    memset(out, 0, sizeof out);
    int verdict = certify(mark, 16, hallmark, out, 0x80);
    static const char *names[] = {"REJECT_STATE", "REJECT_TOKEN", "ACCEPTED"};
    printf("[*] verdict     : %d (%s)\n", verdict,
           verdict >= 0 && verdict <= 2 ? names[verdict] : "?");
    if (verdict == 2)
        printf("[+] certificate : %s\n", out);
    return 0;
}

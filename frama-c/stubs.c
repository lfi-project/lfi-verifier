// Trusted ACSL contracts for the disarm64 decoder library.
// WP uses these specs when reasoning about callers.

#include "disarm64.h"

/*@ requires \valid(ddi);
    assigns *ddi;
*/
void da64_decode(uint32_t inst, struct Da64Inst *ddi) {
    ddi->mnem = DA64I_UNKNOWN;
    for (unsigned i = 0; i < 5; i++)
        ddi->ops[i] = (struct Da64Op){0};
    ddi->imm64 = 0;
}

/*@ requires \valid_read(ddi);
    requires \valid(buf128 + (0 .. 127));
    assigns buf128[0 .. 127];
*/
void da64_format(const struct Da64Inst *ddi, char *buf128) {
    buf128[0] = '\0';
}

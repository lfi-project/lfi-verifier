#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

struct BDDNode {
    uint16_t v;
    uint16_t lo;
    uint16_t hi;
    uint8_t terminal_hi;
    uint8_t terminal_lo;
};

static uint8_t lookup(struct BDDNode *nodes, struct BDDNode *n, uint8_t *input) {
    uint8_t bit = (input[n->v/8] >> (7 - (n->v % 8))) & 1;
    if (bit) {
        if (n->terminal_hi)
            return n->hi;
        return lookup(nodes, &nodes[n->hi], input);
    }

    if (n->terminal_lo)
        return n->lo;
    return lookup(nodes, &nodes[n->lo], input);
}

extern struct BDDNode lfi_bdd_data[] asm("lfi_bdd_data");

// This number comes from the BDD generator.
#define BDD_ENTRY 3825

uint8_t lfi_x86_bdd(uint8_t *input) {
    uint8_t size = lookup(lfi_bdd_data, &lfi_bdd_data[BDD_ENTRY], input);
    return size;
}

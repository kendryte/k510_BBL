#ifndef _RISCV_PLIC_SW_H
#define _RISCV_PLIC_SW_H

#include <stdint.h>

#define SW_PRIORITY_BASE	0x4

#define SW_PENDING_BASE		0x1000
#define SW_PENDING_PER_HART	0x8

#define SW_ENABLE_BASE		0x2000
#define SW_ENABLE_PER_HART	0x80

#define SW_CONTEXT_BASE		0x200000
#define SW_CONTEXT_PER_HART	0x1000
#define SW_CONTEXT_CLAIM	0x4

#define SW_HART_MASK		0x80808080

typedef struct {
  int hart_id;
  int source_id;
  volatile uint32_t* enable;
  volatile uint32_t* pending;
  volatile uint32_t* claim;
} plic_sw_t;

/* Claim interrupt to clean interrupt pending bit*/
void plic_sw_claim(void);

/* Complete interrupt to get next interrupt */
void plic_sw_complete(void);

/* Trigger software interrupt to another hart */
void plic_sw_pending(int to);

/* Get pending status of specific hart */
uint32_t plic_sw_get_pending(uint32_t who);

#endif /* _RISCV_PLIC_SW_H */

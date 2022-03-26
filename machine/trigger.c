#include "trigger.h"
#include "encoding.h"
#include "mtrap.h"
#include "atomic.h"

/* Record the status of trigger used by M-mode */
static struct trigger_module trigger_modules[][TRIGGER_MAX] = {
  [0 ... MAX_HARTS - 1][0 ... TRIGGER_MAX - 1] = {
    .used = 0, .type = TRIGGER_TYPE_MCONTROL} };
static int total_triggers = TRIGGER_MAX;
static spinlock_t trigger_lock = SPINLOCK_INIT;

void trigger_init(void)
{
  uintptr_t tselect, tinfo;
  int i;

  for (i = 0; i < TRIGGER_MAX; i++) {
    write_csr(tselect, i);
    tselect = read_csr(tselect);
    if (i != tselect)
      break;

    tinfo = read_csr(tinfo);
    if (tinfo == 1)
      break;
  }

  /* Only use the minimum number of trigger modules of all harts. */
  spinlock_lock(&trigger_lock);
  if (total_triggers > i)
    total_triggers = i;
  spinlock_unlock(&trigger_lock);
}

static int trigger_set_tselect(int val)
{
  uintptr_t ret;

  write_csr(tselect, val);
  ret = read_csr(tselect);

  if (ret != val)
    return -1;

  return 0;
}

static int trigger_set_tdata1(uintptr_t val)
{
  uintptr_t ret;

  write_csr(tdata1, val);
  ret = read_csr(tdata1);

  if (ret != val)
    return -1;

  return 0;
}

static int trigger_set_tdata2(uintptr_t val)
{
  uintptr_t ret;

  write_csr(tdata2, val);
  ret = read_csr(tdata2);

  if (ret != val)
    return -1;

  return 0;
}

/* The triggers may be used by Debugger */
static int trigger_used_by_dmode(int num)
{
  int dmode;
  trigger_set_tselect(num);
  dmode = (read_csr(tdata1) & TDATA1_OFFSET_DMOEE);
  return dmode;
}

static int trigger_get_free(void)
{
  int i, hartid = read_csr(mhartid);
  for (i = 0; i < total_triggers; i++) {
    if (!trigger_modules[hartid][i].used && !trigger_used_by_dmode(i))
      break;
  }
  return i;
}

static int trigger_get_used_by_type(int type)
{
  int i, hartid = read_csr(mhartid);
  for (i = 0; i < total_triggers; i++) {
    if (trigger_modules[hartid][i].type == type
        && trigger_modules[hartid][i].used)
      break;
  }
  return i;
}

/* If there is no used trigger of the type, find a free one */
static int trigger_get_available(int type)
{
  int num = trigger_get_used_by_type(type);
  if (!TRIGGER_SUPPORT(num)) {
    num = trigger_get_free();
  }
  return num;
}

int trigger_set_icount(uintptr_t count, unsigned int m,
                       unsigned int s, unsigned int u)
{
  uintptr_t val;
  int num, err;
  int hartid = read_csr(mhartid);

  num = trigger_get_available(TRIGGER_TYPE_ICOUNT);

  if (!TRIGGER_SUPPORT(num)) {
    printm("machine mode: trigger %d is not supported.\n", num);
    return -1;
  }

  err = trigger_set_tselect(num);
  if (err)
    return -1;

  if (!TRIGGER_SUPPORT_TYPE(TRIGGER_TYPE_ICOUNT)) {
    printm("machine mode: trigger %d is not support %d type.\n",
            num, TRIGGER_TYPE_ICOUNT);
    return -1;
  }

  val = (TRIGGER_TYPE_ICOUNT << TDATA1_OFFSET_TYPE)
         | (count << ICOUNT_OFFSET_COUNT)
         | (m << ICOUNT_OFFSET_M)
         | (s << ICOUNT_OFFSET_S)
         | (u << ICOUNT_OFFSET_U);
  err = trigger_set_tdata1(val);
  if (err)
    return -1;

  if (u) {
    trigger_modules[hartid][num].used = 1;
    trigger_modules[hartid][num].type = TRIGGER_TYPE_ICOUNT;
  } else {
    trigger_modules[hartid][num].used = 0;
  }

  return err;
}

int trigger_set_itrigger(uintptr_t interrupt, unsigned int m,
                         unsigned int s, unsigned int u)
{
  uintptr_t val;
  int num, err;
  int hartid = read_csr(mhartid);

  num = trigger_get_available(TRIGGER_TYPE_ITRIGGER);

  if (!TRIGGER_SUPPORT(num))
    return -1;
  if (!TRIGGER_SUPPORT(num)) {
    printm("machine mode: trigger %d is not supported.\n", num);
    return -1;
  }

  err = trigger_set_tselect(num);
  if (err)
    return -1;

  if (!TRIGGER_SUPPORT_TYPE(TRIGGER_TYPE_ITRIGGER)) {
    printm("machine mode: trigger %d is not support %d type.\n",
            num, TRIGGER_TYPE_ITRIGGER);
    return -1;
  }

  val = (TRIGGER_TYPE_ITRIGGER << TDATA1_OFFSET_TYPE)
         | (m << ITRIGGER_OFFSET_M)
         | (s << ITRIGGER_OFFSET_S)
         | (u << ITRIGGER_OFFSET_U);
  err = trigger_set_tdata1(val);
  if (err)
    return -1;

  err = trigger_set_tdata2(interrupt);
  if (err)
    return -1;

  if (u) {
    trigger_modules[hartid][num].used = 1;
    trigger_modules[hartid][num].type = TRIGGER_TYPE_ITRIGGER;
  } else {
    trigger_modules[hartid][num].used = 0;
  }

  return err;
}

int trigger_set_etrigger(uintptr_t exception, unsigned int m,
                         unsigned int s, unsigned int u)
{
  uintptr_t val;
  int num, err;
  int hartid = read_csr(mhartid);

  num = trigger_get_available(TRIGGER_TYPE_ETRIGGER);

  if (!TRIGGER_SUPPORT(num)) {
    printm("machine mode: trigger %d is not supported.\n", num);
    return -1;
  }

  err = trigger_set_tselect(num);
  if (err)
    return -1;

  if (!TRIGGER_SUPPORT_TYPE(TRIGGER_TYPE_ETRIGGER)) {
    printm("machine mode: trigger %d is not support %d type.\n",
            num, TRIGGER_TYPE_ETRIGGER);
    return -1;
  }

  val = (TRIGGER_TYPE_ETRIGGER << TDATA1_OFFSET_TYPE)
         | (m << ETRIGGER_OFFSET_M)
         | (s << ETRIGGER_OFFSET_S)
         | (u << ETRIGGER_OFFSET_U);
  err = trigger_set_tdata1(val);
  if (err)
    return -1;

  err = trigger_set_tdata2(exception);
  if (err)
    return -1;

  if (u) {
    trigger_modules[hartid][num].used = 1;
    trigger_modules[hartid][num].type = TRIGGER_TYPE_ETRIGGER;
  } else {
    trigger_modules[hartid][num].used = 0;
  }

  return err;
}

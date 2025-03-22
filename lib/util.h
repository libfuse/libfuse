#ifndef FUSE_UTIL_H_
#define FUSE_UTIL_H_

#include <stdint.h>

#define ROUND_UP(val, round_to) (((val) + (round_to - 1)) & ~(round_to - 1))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

int libfuse_strtol(const char *str, long *res);

/**
 * Return the low bits of a number
 */
static inline uint32_t fuse_lower_32_bits(uint64_t nr)
{
	return (uint32_t)(nr & 0xffffffff);
}

/**
 * Return the high bits of a number
 */
static inline uint64_t fuse_higher_32_bits(uint64_t nr)
{
	return nr & ~0xffffffffULL;
}

#ifndef FUSE_VAR_UNUSED
#define FUSE_VAR_UNUSED(var) (__attribute__((unused)) var)
#endif

#endif

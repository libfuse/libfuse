#ifndef FUSE_UTIL_H_
#define FUSE_UTIL_H_

#include <stdint.h>
#include <stdbool.h>

#define max(x, y) ((x) > (y) ? (x) : (y))
#define min(x, y) ((x) < (y) ? (x) : (y))

#define ROUND_UP(val, round_to) (((val) + (round_to - 1)) & ~(round_to - 1))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

struct fuse_conn_info;

int libfuse_strtol(const char *str, long *res);
void fuse_set_thread_name(const char *name);

/**
 * @brief Abort if FUSE_PEDANTIC=1 is set in the environment.
 *
 * @param[in] func  Calling function, for the log line.
 */
void fuse_panic_if_pedantic(const char *func);

/*
 * Crash on a path that cannot be reached without a bug. A file system in
 * production is better off carrying on, so this only bites where the
 * environment asks for it.
 */
#define PANIC_IF_PEDANTIC() fuse_panic_if_pedantic(__func__)

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
#define FUSE_VAR_UNUSED __attribute__((__unused__))
#endif

#define container_of(ptr, type, member)                      \
	({                                                   \
		unsigned long __mptr = (unsigned long)(ptr); \
		((type *)(__mptr - offsetof(type, member))); \
	})

#if __has_attribute(__fallthrough__)
#define fallthrough __attribute__((__fallthrough__))
#else
#define fallthrough do {} while (0)
#endif

static inline uint64_t round_up(uint64_t b, unsigned int align)
{
	unsigned int m;

	if (align == 0)
		return b;
	m = b % align;
	if (m)
		b += align - m;
	return b;
}

static inline uint64_t round_down(uint64_t b, unsigned int align)
{
	unsigned int m;

	if (align == 0)
		return b;
	m = b % align;
	return b - m;
}

static inline uint64_t howmany(uint64_t b, unsigned int align)
{
	unsigned int m;

	if (align == 0)
		return b;
	m = (b % align) ? 1 : 0;
	return (b / align) + m;
}

#endif /* FUSE_UTIL_H_ */

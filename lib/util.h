#define ROUND_UP(val, round_to) (((val) + (round_to - 1)) & ~(round_to - 1))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

int libfuse_strtol(const char *str, long *res);

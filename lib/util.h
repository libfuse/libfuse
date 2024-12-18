#define ROUND_UP(val, round_to) (((val) + (round_to - 1)) & ~(round_to - 1))

int libfuse_strtol(const char *str, long *res);

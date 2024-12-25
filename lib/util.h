#pragma once
#ifndef LIBFUSE_UTIL_H
#define LIBFUSE_UTIL_H

#define ROUND_UP(val, round_to) (((val) + (round_to - 1)) & ~(round_to - 1))

#if (__STDC_VERSION__ >= 202311L) || (__cplusplus >= 202002L)
#define likely(x) (x) [[likely]]
#define unlikely(x) (x) [[unlikely]]
#else
#define likely(x) (__builtin_expect(!!(x), 1))
#define unlikely(x) (__builtin_expect(!!(x), 0))
#endif

int libfuse_strtol(const char *str, long *res);

#endif // LIBFUSE_UTIL_H

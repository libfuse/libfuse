#include <stdio.h>

int main(void) {
#ifdef MESON_IS_SUBPROJECT
	fprintf(stderr, "libfuse tests were skipped because it's a meson subproject.\n"
			"If you wish to run them try:\n"
			"'cd <srcdir>/subprojects/libfuse && meson . build && cd build && python3 -m pytest test/' instead");
	return 77; /* report as a skipped test */
#else
	fprintf(stderr, "\x1B[31m\e[1m"
		"This is not the command you are looking for.\n"
		"You probably want to run 'python3 -m pytest test/' instead"
		"\e[0m\n");
	return 1;
#endif
}

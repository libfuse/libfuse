#include <stdio.h>

int main(void) {
	fprintf(stderr, "\x1B[31m\e[1m"
		"This is not the command you are looking for.\n"
		"You probably want to run 'ninja tests' instead "
		"(note the 's' at the end).\n"
		"\e[0m");
	return 1;
}

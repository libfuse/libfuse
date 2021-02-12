/*
 * Prints each directory entry and its inode as returned by 'readdir'.
 * Skips '.' and '..' because readdir is not required to return them and
 * some of our examples don't.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>

int main(int argc, char* argv[])
{
    DIR* dirp;
    struct dirent* dent;

    if (argc != 2) {
        fprintf(stderr, "Usage: readdir_inode dir\n");
        return 1;
    }

    dirp = opendir(argv[1]);
    if (dirp == NULL) {
        perror("failed to open directory");
        return 2;
    }

    errno = 0;
    dent = readdir(dirp);
    while (dent != NULL) {
        if (strcmp(dent->d_name, ".") != 0 && strcmp(dent->d_name, "..") != 0) {
            printf("%llu %s\n", (unsigned long long)dent->d_ino, dent->d_name);
        }
        dent = readdir(dirp);
    }
    if (errno != 0) {
        perror("failed to read directory entry");
        return 3;
    }

    closedir(dirp);

    return 0;
}

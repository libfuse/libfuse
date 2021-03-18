/*
 * Prints each directory entry, its inode and d_type as returned by 'readdir'.
 * Skips '.' and '..' because readdir is not required to return them and
 * some of our examples don't. However if they are returned, their d_type
 * should be valid.
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
            printf("%llu %d %s\n", (unsigned long long)dent->d_ino,
			(int)dent->d_type, dent->d_name);
            if ((long long)dent->d_ino < 0)
               fprintf(stderr,"%s : bad d_ino %llu\n",
                        dent->d_name, (unsigned long long)dent->d_ino);
            if ((dent->d_type < 1) || (dent->d_type > 15))
               fprintf(stderr,"%s : bad d_type %d\n",
                        dent->d_name, (int)dent->d_type);
        } else {
            if (dent->d_type != DT_DIR)
               fprintf(stderr,"%s : bad d_type %d\n",
                        dent->d_name, (int)dent->d_type);
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

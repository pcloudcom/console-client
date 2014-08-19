#include <stdio.h>

#include "psynclib.h"

int main()
{
	psync_init();
	psync_start_sync(NULL, NULL);
	psync_fs_start();
	printf("Press enter to exit/umount\n");
	getc(stdin);
	psync_fs_stop();
	psync_destroy();
	return 0;
}

/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
#include "fuse_i.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pagemap.h>


static int fuse_open(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_open_in arg;

	arg.flags = file->f_flags & ~O_EXCL;
	in.h.opcode = FUSE_OPEN;
	in.h.ino = inode->i_ino;
	in.argsize = sizeof(arg);
	in.arg = &arg;
	request_send(fc, &in, &out);

	return out.h.error;
}

static int fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_read_in arg;
	char *buffer;

	buffer = kmap(page);

	arg.offset = page->index << PAGE_CACHE_SHIFT;
	arg.size = PAGE_CACHE_SIZE;

	in.h.opcode = FUSE_READ;
	in.h.ino = inode->i_ino;
	in.argsize = sizeof(arg);
	in.arg = &arg;
	out.argsize = PAGE_CACHE_SIZE;
	out.argvar = 1;
	out.arg = buffer;

	request_send(fc, &in, &out);
	if(!out.h.error) {
		if(out.argsize < PAGE_CACHE_SIZE) 
			memset(buffer + out.argsize, 0,
			       PAGE_CACHE_SIZE - out.argsize);
		SetPageUptodate(page);
	}

	kunmap(page);
	UnlockPage(page);

	return out.h.error;
}

static struct file_operations fuse_file_operations = {
	open:		fuse_open,
	read:		generic_file_read,
};

static struct address_space_operations fuse_file_aops  = {
	readpage:	fuse_readpage,
};

void fuse_init_file_inode(struct inode *inode)
{
	inode->i_fop = &fuse_file_operations;
	inode->i_data.a_ops = &fuse_file_aops;
}

/* 
 * Local Variables:
 * indent-tabs-mode: t
 * c-basic-offset: 8
 * End:
 */

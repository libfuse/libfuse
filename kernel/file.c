/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001  Miklos Szeredi (mszeredi@inf.bme.hu)

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/
#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/slab.h>


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
	if(!out.h.error)
		invalidate_inode_pages(inode);

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

static int write_buffer(struct inode *inode, struct page *page,
			unsigned offset, size_t count)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_write_in *arg;
	size_t argsize;
	char *buffer;

	argsize = offsetof(struct fuse_write_in, buf) + count;
	arg = kmalloc(argsize, GFP_KERNEL);
	if(!arg)
		return -ENOMEM;

	arg->offset = (page->index << PAGE_CACHE_SHIFT) + offset;
	arg->size = count;
	buffer = kmap(page);
	memcpy(arg->buf, buffer + offset, count);
	kunmap(page);
	
	in.h.opcode = FUSE_WRITE;
	in.h.ino = inode->i_ino;
	in.argsize = argsize;
	in.arg = arg;
	request_send(fc, &in, &out);
	kfree(arg);

	return out.h.error;
}


static int fuse_writepage(struct page *page)
{
	struct inode *inode = page->mapping->host;
	unsigned count;
	unsigned long end_index;
	int err;
	
	end_index = inode->i_size >> PAGE_CACHE_SHIFT;
	if(page->index < end_index)
		count = PAGE_CACHE_SIZE;
	else {
		count = inode->i_size & (PAGE_CACHE_SIZE - 1);
		err = -EIO;
		if(page->index > end_index || count == 0)
			goto out;

	}
	err = write_buffer(inode, page, 0, count);
  out:
	UnlockPage(page);
	return 0;
}


static int fuse_prepare_write(struct file *file, struct page *page,
			      unsigned offset, unsigned to)
{
	/* No op */
	return 0;
}

static int fuse_commit_write(struct file *file, struct page *page,
			     unsigned offset, unsigned to)
{
	int err;
	struct inode *inode = page->mapping->host;

	err = write_buffer(inode, page, offset, to - offset);
	if(!err) {
		loff_t pos = (page->index << PAGE_CACHE_SHIFT) + to;
		if(pos > inode->i_size)
			inode->i_size = pos;
	}
	return err;
}

static struct file_operations fuse_file_operations = {
	open:		fuse_open,
	read:		generic_file_read,
	write:		generic_file_write,
	mmap:		generic_file_mmap,
};

static struct address_space_operations fuse_file_aops  = {
	readpage:	fuse_readpage,
	writepage:	fuse_writepage,
	prepare_write:	fuse_prepare_write,
	commit_write:	fuse_commit_write,
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

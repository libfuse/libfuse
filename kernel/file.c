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
	struct fuse_open_in inarg;

	/* If opening the root node, no lookup has been performed on
	   it, so the attributes must be refreshed */
	if(inode->i_ino == FUSE_ROOT_INO) {
		int err = fuse_getattr(inode);
		if(err)
		 	return err;
	}

	memset(&inarg, 0, sizeof(inarg));
	inarg.flags = file->f_flags & ~O_EXCL;

	in.h.opcode = FUSE_OPEN;
	in.h.ino = inode->i_ino;
	in.numargs = 1;
	in.args[0].size = sizeof(inarg);
	in.args[0].value = &inarg;
	request_send(fc, &in, &out);
	if(!out.h.error && !(fc->flags & FUSE_KERNEL_CACHE))
		invalidate_inode_pages(inode);

	return out.h.error;
}

static int fuse_release(struct inode *inode, struct file *file)
{
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in *in = NULL;
	struct fuse_open_in *inarg = NULL;

	in = kmalloc(sizeof(struct fuse_in), GFP_NOFS);
	if(!in)
		return -ENOMEM;
	memset(in, 0, sizeof(struct fuse_in));
	
	inarg = kmalloc(sizeof(struct fuse_open_in), GFP_NOFS);
	if(!inarg) 
		goto out_free;
	memset(inarg, 0, sizeof(struct fuse_open_in));

	inarg->flags = file->f_flags & ~O_EXCL;

	in->h.opcode = FUSE_RELEASE;
	in->h.ino = inode->i_ino;
	in->numargs = 1;
	in->args[0].size = sizeof(struct fuse_open_in);
	in->args[0].value = inarg;
	if(!request_send_noreply(fc, in))
		return 0;

 out_free:
	kfree(inarg);
	kfree(in);
	return 0;
}


static int fuse_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct fuse_conn *fc = INO_FC(inode);
	struct fuse_in in = FUSE_IN_INIT;
	struct fuse_out out = FUSE_OUT_INIT;
	struct fuse_read_in inarg;
	char *buffer;

	buffer = kmap(page);
	
	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = (unsigned long long) page->index << PAGE_CACHE_SHIFT;
	inarg.size = PAGE_CACHE_SIZE;

	in.h.opcode = FUSE_READ;
	in.h.ino = inode->i_ino;
	in.numargs = 1;
	in.args[0].size = sizeof(inarg);
	in.args[0].value = &inarg;
	out.argvar = 1;
	out.numargs = 1;
	out.args[0].size = PAGE_CACHE_SIZE;
	out.args[0].value = buffer;

	request_send(fc, &in, &out);
	if(!out.h.error) {
		size_t outsize = out.args[0].size;
		if(outsize < PAGE_CACHE_SIZE) 
			memset(buffer + outsize, 0, PAGE_CACHE_SIZE - outsize);
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
	struct fuse_write_in inarg;
	char *buffer;

	buffer = kmap(page);

	memset(&inarg, 0, sizeof(inarg));
	inarg.offset = ((unsigned long long) page->index << PAGE_CACHE_SHIFT) +
		offset;
	inarg.size = count;
	
	in.h.opcode = FUSE_WRITE;
	in.h.ino = inode->i_ino;
	in.numargs = 2;
	in.args[0].size = sizeof(inarg);
	in.args[0].value = &inarg;
	in.args[1].size = count;
	in.args[1].value = buffer + offset;
	request_send(fc, &in, &out);

	kunmap(page);

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
	release:        fuse_release,
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

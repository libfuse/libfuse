/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2024 DataDirect Networks.

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

#include <linux/limits.h>
#define FUSE_USE_VERSION 317

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <iostream>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <string_view>
#include <cstdint>
#include <fuse_lowlevel.h>

#define MEMFS_ATTR_TIMEOUT 0.0
#define MEMFS_ENTRY_TIMEOUT 0.0

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

class Inodes;
class Inode;
class Dentry;

static void memfs_panic(std::string_view message);

struct DirHandle {
	std::vector<std::pair<std::string, const Dentry *> > entries;
	size_t offset;

	DirHandle(const std::vector<std::pair<std::string, const Dentry *> >
			  &entries)
		: entries(entries)
		, offset(0)
	{
	}
};

class Inode {
    private:
	uint64_t ino; // Unique inode number
	std::string name;
	bool is_dir_;
	time_t ctime;
	time_t mtime;
	time_t atime;
	mode_t mode;
	std::vector<char> content;
	std::vector<Dentry *> dentries;
	mutable std::mutex mutex;
	uint64_t nlookup;
	mutable std::mutex attr_mutex;
	std::atomic<nlink_t> nlink;
	uid_t uid;
	gid_t gid;

	friend class Inodes;

    public:
	Inode(uint64_t ino, const std::string &n, bool dir)
		: ino(ino)
		, name(n)
		, is_dir_(dir)
		, ctime(time(NULL))
		, mtime(ctime)
		, atime(ctime)
		, mode(dir ? S_IFDIR | 0755 : S_IFREG | 0644)
		, nlookup(1)
		, nlink(dir ? 2 : 1)
		, uid(0)
		, gid(0)
	{
	}

	uint64_t get_ino() const
	{
		return ino;
	}

	// Method to lock the mutex
	void lock() const
	{
		mutex.lock();
	}

	// Method to unlock the mutex
	void unlock() const
	{
		mutex.unlock();
	}

	void inc_lookup()
	{
		std::lock_guard<std::mutex> lock(mutex);
		nlookup++;
	}

	uint64_t dec_lookup(uint64_t count)
	{
		std::unique_lock<std::mutex> lock(mutex);
		if (nlookup < count) {
			lock.unlock();
			memfs_panic("Lookup count mismatch detected");
		}
		nlookup -= count;
		return nlookup;
	}

	const std::string &get_name() const
	{
		return name;
	}
	bool is_dir() const
	{
		return is_dir_;
	}
	time_t get_ctime() const
	{
		return ctime;
	}
	time_t get_mtime() const
	{
		return mtime;
	}
	mode_t get_mode() const
	{
		return mode;
	}

	size_t content_size() const
	{
		return content.size();
	}

	void read_content(char *buf, size_t size, off_t offset) const
	{
		size_t bytes_to_read = std::min(size, content.size() - offset);
		std::copy(content.begin() + offset,
			  content.begin() + offset + bytes_to_read, buf);
	}

	void write_content(const char *buf, size_t size, off_t offset)
	{
		std::lock_guard<std::mutex> lock(mutex);
		if (offset + size > content.size()) {
			content.resize(offset + size);
		}
		std::copy(buf, buf + size, content.begin() + offset);
		mtime = time(NULL);
	}

	void set_uid(uid_t _uid)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		uid = _uid;
	}

	void set_gid(gid_t _gid)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		gid = _gid;
	}

	void set_mode(mode_t new_mode)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		mode = new_mode;
	}

	void set_atime(const struct timespec &_atime)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		atime = _atime.tv_sec;
	}

	void set_mtime(const struct timespec &_mtime)
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		mtime = _mtime.tv_sec;
	}

	void truncate(off_t size)
	{
		std::lock_guard<std::mutex> lock(mutex);
		std::lock_guard<std::mutex> attr_lock(attr_mutex);
		if (size < content.size()) {
			content.resize(size);
		} else if (size > content.size()) {
			content.resize(size, 0);
		}
		mtime = time(NULL);
	}

	void get_attr(struct stat *stbuf) const
	{
		std::lock_guard<std::mutex> lock(attr_mutex);
		stbuf->st_ino = ino;
		stbuf->st_mode = mode;
		stbuf->st_nlink = nlink;
		stbuf->st_uid = uid;
		stbuf->st_gid = gid;
		stbuf->st_size = content.size();
		stbuf->st_blocks = DIV_ROUND_UP(content.size(), 512);
		stbuf->st_atime = atime;
		stbuf->st_mtime = mtime;
		stbuf->st_ctime = ctime;
	}

	bool is_empty() const
	{
		return dentries.empty();
	}

	void inc_nlink()
	{
		nlink++;
	}

	nlink_t dec_nlink()
	{
		nlink_t old_value =
			nlink.fetch_sub(1, std::memory_order_relaxed);
		if (old_value == 0) {
			memfs_panic("Attempting to decrement nlink below zero");
		}
		return old_value - 1;
	}

	/**
	  * Methods that need Dentry knowledge
	  */
	int add_child_locked(const std::string &name, Dentry *child_dentry);
	int add_child(const std::string &name, Dentry *child_dentry);
	int remove_child(const std::string &name);
	std::vector<std::pair<std::string, const Dentry *> >
	get_children() const;
	Dentry *find_child_locked(const std::string &name) const;
	Dentry *find_child(const std::string &name) const;
};

class Dentry {
    public:
	std::string name;
	Inode *inode;

	Dentry(const std::string &n, Inode *i)
		: name(n)
		, inode(i)
	{
	}

	uint64_t get_ino() const
	{
		return inode->get_ino();
	}
	bool is_dir() const
	{
		return inode->is_dir();
	}
	const std::string &get_name() const
	{
		return name;
	}

	time_t get_ctime() const
	{
		return inode->get_ctime();
	}
	time_t get_mtime() const
	{
		return inode->get_mtime();
	}
	mode_t get_mode() const
	{
		return inode->get_mode();
	}
	size_t content_size() const
	{
		return inode->content_size();
	}

	Inode *get_inode() const
	{
		return inode;
	}

	void inc_lookup()
	{
		inode->inc_lookup();
	}
};

class Inodes {
    private:
	std::unordered_map<uint64_t, std::unique_ptr<Inode> > inodes;
	mutable std::shared_mutex inodes_mutex;
	std::atomic<uint64_t> next_ino{ FUSE_ROOT_ID + 1 };
	std::mutex mutex;

    public:
	Inodes()
	{
		auto root = std::make_unique<Inode>(FUSE_ROOT_ID, "/", true);
		root->mode = S_IFDIR | 0755;
		root->nlink = 2; // . and ..
		inodes[FUSE_ROOT_ID] = std::move(root);
	}

	// New lock method
	void lock()
	{
		inodes_mutex.lock();
	}

	// New unlock method
	void unlock()
	{
		inodes_mutex.unlock();
	}

	void erase_locked(Inode *inode)
	{
		if (inode) {
			inodes.erase(inode->get_ino());
		}
	}

	void erase(Inode *inode)
	{
		std::unique_lock<std::shared_mutex> lock(inodes_mutex);
		erase_locked(inode);
	}

	Inode *find_locked(fuse_ino_t ino)
	{
		auto it = inodes.find(ino);
		if (it == inodes.end()) {
			return nullptr;
		}
		return it->second.get();
	}

	Inode *find(fuse_ino_t ino)
	{
		std::shared_lock lock(inodes_mutex);
		return find_locked(ino);
	}

	Inode *create(const std::string &name, bool is_dir, mode_t mode)
	{
		std::unique_lock<std::shared_mutex> lock(inodes_mutex);

		uint64_t ino = next_ino.fetch_add(1, std::memory_order_relaxed);
		auto new_inode = std::make_unique<Inode>(ino, name, is_dir);
		new_inode->set_mode(mode);

		auto [it, inserted] = inodes.emplace(ino, std::move(new_inode));

		if (!inserted) {
			// This should never happen, but let's handle it just in case
			return nullptr;
		}

		return it->second.get();
	}

	size_t size()
	{
		std::lock_guard<std::mutex> lock(mutex);
		return inodes.size();
	}
};

int Inode::add_child_locked(const std::string &name, Dentry *child_dentry)
{
	if (!is_dir_) {
		return ENOTDIR;
	}

	// Check if a child with this name already exists
	auto it = std::find_if(dentries.begin(), dentries.end(),
			       [&name](const Dentry *dentry) {
				       return dentry->get_name() == name;
			       });

	if (it != dentries.end()) {
		return EEXIST;
	}

	dentries.push_back(child_dentry);
	if (child_dentry->is_dir()) {
		nlink++;
	}
	return 0;
}

int Inode::add_child(const std::string &name, Dentry *child_dentry)
{
	std::lock_guard<std::mutex> lock(mutex);
	return add_child_locked(name, child_dentry);
}

int Inode::remove_child(const std::string &name)
{
	if (!is_dir_) {
		return ENOTDIR;
	}

	auto it = std::find_if(dentries.begin(), dentries.end(),
			       [&name](const Dentry *dentry) {
				       return dentry->get_name() == name;
			       });

	if (it == dentries.end()) {
		return ENOENT;
	}

	Dentry *child_dentry = *it;
	dentries.erase(it);

	if (child_dentry->is_dir()) {
		nlink--;
	}

	delete child_dentry;
	return 0;
}
Dentry *Inode::find_child_locked(const std::string &name) const
{
	if (!is_dir_) {
		return nullptr;
	}

	auto it = std::find_if(dentries.begin(), dentries.end(),
			       [&name](const Dentry *dentry) {
				       return dentry->get_name() == name;
			       });

	return (it != dentries.end()) ? *it : nullptr;
}

Dentry *Inode::find_child(const std::string &name) const
{
	std::lock_guard<std::mutex> lock(mutex);
	return find_child_locked(name);
}

std::vector<std::pair<std::string, const Dentry *> > Inode::get_children() const
{
	if (!is_dir_) {
		return {}; // Return an empty vector if this is not a directory
	}

	std::vector<std::pair<std::string, const Dentry *> > children;
	children.reserve(dentries.size());

	for (size_t i = 0; i < dentries.size(); ++i) {
		const Dentry *dentry = dentries[i];
		std::string name = dentry->get_name();
		children.emplace_back(name, dentry);
	}

	return children;
}
static Inodes Inodes;

static void memfs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	auto *parentInode = Inodes.find(parent);

	if (!parentInode) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	if (!parentInode->is_dir()) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	Dentry *child = parentInode->find_child(name);
	if (!child) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	struct fuse_entry_param e;
	memset(&e, 0, sizeof(e));
	e.ino = child->get_ino();
	e.attr_timeout = MEMFS_ATTR_TIMEOUT;
	e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
	e.attr.st_ino = child->get_ino();
	e.attr.st_mode = child->get_mode();
	e.attr.st_nlink = child->is_dir() ? 2 : 1;

	child->inc_lookup();

	fuse_reply_entry(req, &e);
}

static void memfs_getattr(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	fuse_ino_t actual_ino = fi ? fi->fh : ino;
	if (actual_ino == 0) {
		fuse_reply_err(req, EBADF);
		return;
	}

	auto *inode_data = Inodes.find(actual_ino);
	if (!inode_data) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	struct stat stbuf;
	inode_data->get_attr(&stbuf);
	stbuf.st_ino = actual_ino; // Ensure the correct inode number is set

	fuse_reply_attr(req, &stbuf, MEMFS_ATTR_TIMEOUT);
}

static void memfs_create(fuse_req_t req, fuse_ino_t parent, const char *name,
			 mode_t mode, struct fuse_file_info *fi)
{
	auto *parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	if (parentInode->find_child(name)) {
		fuse_reply_err(req, EEXIST);
		return;
	}

	Inode *new_inode = Inodes.create(name, false, mode);
	if (!new_inode) {
		fuse_reply_err(req, EIO);
		return;
	}

	// Create a new Dentry and add it to the parent
	Dentry *new_dentry = new Dentry(name, new_inode);

	//std::cout << "Debug: Created new Dentry at address "
	//	  << (void *)new_dentry << ", name: '" << name
	//	  << "', inode address: " << (void *)new_inode << std::endl;

	parentInode->add_child(name, new_dentry);

	struct fuse_entry_param e;
	memset(&e, 0, sizeof(e));
	e.ino = new_inode->get_ino();
	e.attr_timeout = MEMFS_ATTR_TIMEOUT;
	e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
	new_inode->get_attr(&e.attr);

	fi->fh = e.ino;
	fuse_reply_create(req, &e, fi);
}

static void memfs_write(fuse_req_t req, fuse_ino_t ino, const char *buf,
			size_t size, off_t offset,
			[[maybe_unused]] struct fuse_file_info *fi)
{
	Inode *inode = Inodes.find(ino);
	if (!inode) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	if (inode->is_dir()) {
		fuse_reply_err(req, EISDIR);
		return;
	}

	inode->write_content(buf, size, offset);
	fuse_reply_write(req, size);
}

static void memfs_read(fuse_req_t req, fuse_ino_t ino, size_t size,
		       off_t offset, [[maybe_unused]] struct fuse_file_info *fi)
{
	Inode *inode = Inodes.find(ino);
	if (!inode || inode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	inode->lock();

	if (offset >= inode->content_size()) {
		fuse_reply_buf(req, nullptr, 0);
		inode->unlock();
		return;
	}

	std::vector<char> content(
		std::min(size, inode->content_size() - offset));
	inode->read_content(content.data(), content.size(), offset);

	inode->unlock();

	fuse_reply_buf(req, content.data(), content.size());
}

static void memfs_open(fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi)
{
	auto *inode_data = Inodes.find(ino);
	if (!inode_data || inode_data->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	// Use the inode number as the file handle
	fi->fh = ino;
	fuse_reply_open(req, fi);
}

static void memfs_opendir(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	auto *inode = Inodes.find(ino);
	if (!inode || !inode->is_dir()) {
		fuse_reply_err(req, ENOTDIR);
		return;
	}

	// Create a new DirHandle
	auto dir_handle = new DirHandle(inode->get_children());

	// Store the pointer to the DirHandle in fi->fh
	fi->fh = reinterpret_cast<uint64_t>(dir_handle);

	fuse_reply_open(req, fi);
}

static void memfs_readdir(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
			  size_t size, off_t offset, struct fuse_file_info *fi)
{
	auto *dir_handle = reinterpret_cast<DirHandle *>(fi->fh);
	if (!dir_handle) {
		fuse_reply_err(req, EBADF);
		return;
	}

	char *buffer = new char[size];
	size_t buf_size = 0;

	for (off_t i = offset;
	     i < static_cast<off_t>(dir_handle->entries.size()); ++i) {
		const auto &entry = dir_handle->entries[i];
		const std::string &name = entry.first;
		const Dentry *dentry = entry.second;

		struct stat stbuf;
		memset(&stbuf, 0, sizeof(stbuf));
		stbuf.st_ino = dentry->get_inode()->get_ino();
		dentry->get_inode()->get_attr(&stbuf);

		size_t entry_size = fuse_add_direntry(req, nullptr, 0,
						      name.c_str(), nullptr, 0);
		if (buf_size + entry_size > size) {
			break;
		}

		fuse_add_direntry(req, buffer + buf_size, size - buf_size,
				  name.c_str(), &stbuf, i + 1);
		buf_size += entry_size;
	}

	fuse_reply_buf(req, buffer, buf_size);
	delete[] buffer;
}

static void memfs_release(fuse_req_t req, fuse_ino_t ino,
			  struct fuse_file_info *fi)
{
	// No need to remove file handle
	(void)fi;
	(void)ino;
	fuse_reply_err(req, 0);
}

static void memfs_releasedir(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino,
			     struct fuse_file_info *fi)
{
	auto *dir_handle = reinterpret_cast<DirHandle *>(fi->fh);
	delete dir_handle;
	fuse_reply_err(req, 0);
}

static void memfs_panic(std::string_view message)
{
	std::cerr << "MEMFS PANIC: " << message << std::endl;
	std::abort();
}

static void memfs_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	Inodes.lock();
	Inode *inode = Inodes.find_locked(ino);
	uint64_t res;
	if (inode) {
		res = inode->dec_lookup(nlookup);
		if (res == 0)
			Inodes.erase_locked(inode);
	}
	Inodes.unlock();
	fuse_reply_none(req);
}

static void memfs_forget_multi(fuse_req_t req, size_t count,
			       struct fuse_forget_data *forgets)
{
	for (size_t i = 0; i < count; i++) {
		fuse_ino_t ino = forgets[i].ino;
		uint64_t nlookup = forgets[i].nlookup;
		auto *inode_data = Inodes.find(ino);
		if (inode_data) {
			inode_data->dec_lookup(nlookup);
		}
	}
	fuse_reply_none(req);
}

static void memfs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			  int to_set, struct fuse_file_info *fi)
{
	fuse_ino_t actual_ino = fi ? fi->fh : ino;
	if (actual_ino == 0) {
		fuse_reply_err(req, EBADF);
		return;
	}

	auto *inode_data = Inodes.find(actual_ino);
	if (!inode_data) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	inode_data->lock();

	if (to_set & FUSE_SET_ATTR_MODE)
		inode_data->set_mode(attr->st_mode);
	if (to_set & FUSE_SET_ATTR_UID)
		inode_data->set_uid(attr->st_uid);
	if (to_set & FUSE_SET_ATTR_GID)
		inode_data->set_gid(attr->st_gid);
	if (to_set & FUSE_SET_ATTR_SIZE)
		inode_data->truncate(attr->st_size);
	if (to_set & FUSE_SET_ATTR_ATIME)
		inode_data->set_atime(attr->st_atim);
	if (to_set & FUSE_SET_ATTR_MTIME)
		inode_data->set_mtime(attr->st_mtim);

	struct stat st;
	inode_data->get_attr(&st);
	inode_data->unlock();

	fuse_reply_attr(req, &st, MEMFS_ATTR_TIMEOUT);
}

static void memfs_mkdir(fuse_req_t req, fuse_ino_t parent, const char *name,
			mode_t mode)
{
	int error = 0;
	Inode *parentInode = nullptr;
	Inode *new_inode = nullptr;
	Dentry *new_dentry = nullptr;
	struct fuse_entry_param e;

	parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		error = ENOENT;
		goto out;
	}

	new_inode = Inodes.create(name, true, mode | S_IFDIR);
	if (!new_inode) {
		error = EIO;
		goto out;
	}

	new_dentry = new Dentry(name, new_inode);
	error = parentInode->add_child(name, new_dentry);
	if (error != 0) {
		goto out_cleanup;
	}

	memset(&e, 0, sizeof(e));
	e.ino = new_inode->get_ino();
	e.attr_timeout = MEMFS_ATTR_TIMEOUT;
	e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
	new_inode->get_attr(&e.attr);

out:
	if (error == 0) {
		fuse_reply_entry(req, &e);
	} else {
		fuse_reply_err(req, error);
	}
	return;

out_cleanup:
	delete new_dentry;
	Inodes.erase_locked(new_inode);
	goto out;
}

static void memfs_rmdir(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	auto *parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	parentInode->lock();

	auto child_dentry = parentInode->find_child_locked(name);
	if (child_dentry == nullptr) {
		parentInode->unlock();
		fuse_reply_err(req, ENOENT);
		return;
	}

	Inode *child = child_dentry->get_inode();
	if (!child || !child->is_dir() || !child->is_empty()) {
		parentInode->unlock();
		fuse_reply_err(req, child ? (child->is_empty() ? ENOTDIR :
								 ENOTEMPTY) :
					    ENOENT);
		return;
	}

	parentInode->remove_child(name);
	child->dec_nlink(); // This should handle removal if nlink reaches 0

	parentInode->unlock();

	fuse_reply_err(req, 0);
}

static void memfs_unlink(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	auto *parentInode = Inodes.find(parent);
	if (!parentInode || !parentInode->is_dir()) {
		fuse_reply_err(req, ENOENT);
		return;
	}

	parentInode->lock();

	auto child_dentry = parentInode->find_child_locked(name);
	if (child_dentry == nullptr) {
		parentInode->unlock();
		fuse_reply_err(req, ENOENT);
		return;
	}

	Inode *child = child_dentry->get_inode();
	if (!child || child->is_dir()) {
		parentInode->unlock();
		fuse_reply_err(req, child ? EISDIR : ENOENT);
		return;
	}

	parentInode->remove_child(name);
	child->dec_nlink();

	parentInode->unlock();

	fuse_reply_err(req, 0);
}

static void memfs_rename(fuse_req_t req, fuse_ino_t parent, const char *name,
			 fuse_ino_t newparent, const char *newname,
			 unsigned int flags)
{
	int error = 0;
	Inode *parentInode = nullptr;
	Inode *newparentInode = nullptr;
	Dentry *child_dentry = nullptr;
	Dentry *existing_dentry = nullptr;

	if (flags & (RENAME_EXCHANGE | RENAME_NOREPLACE)) {
		fuse_reply_err(req, EINVAL);
		return;
	}

	Inodes.lock();

	parentInode = Inodes.find(parent);
	newparentInode = Inodes.find(newparent);
	if (!parentInode || !parentInode->is_dir() || !newparentInode ||
	    !newparentInode->is_dir()) {
		error = ENOENT;
		goto out_unlock_global;
	}

	parentInode->lock();
	if (parent != newparent) {
		newparentInode->lock();
	}

	child_dentry = parentInode->find_child_locked(name);
	if (child_dentry == nullptr) {
		error = ENOENT;
		goto out_unlock;
	}

	existing_dentry = newparentInode->find_child_locked(newname);
	if (existing_dentry) {
		if (existing_dentry->is_dir()) {
			if (!existing_dentry->get_inode()->is_empty()) {
				error = ENOTEMPTY;
				goto out_unlock;
			}
			newparentInode->dec_nlink();
		}
		newparentInode->remove_child(newname);
		existing_dentry->get_inode()->dec_nlink();
	}

	parentInode->remove_child(name);
	child_dentry->name = newname;
	newparentInode->add_child(newname, child_dentry);

out_unlock:
	parentInode->unlock();
	if (parent != newparent) {
		newparentInode->unlock();
	}

out_unlock_global:
	Inodes.unlock();
	fuse_reply_err(req, error);
}

static void memfs_link(fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
		       const char *newname)
{
	int error = 0;
	Inode *src_inode = nullptr;
	Inode *parent_inode = nullptr;
	struct fuse_entry_param e;
	std::unique_ptr<Dentry> new_dentry;

	Inodes.lock();

	src_inode = Inodes.find(ino);
	if (!src_inode) {
		error = ENOENT;
		goto out_unlock_global;
	}

	parent_inode = Inodes.find(newparent);
	if (!parent_inode || !parent_inode->is_dir()) {
		error = ENOENT;
		goto out_unlock_global;
	}

	parent_inode->lock();

	// Check if the new name already exists in the parent directory
	if (parent_inode->find_child_locked(newname) != nullptr) {
		error = EEXIST;
		goto out_unlock_parent;
	}

	src_inode->inc_nlink();

	new_dentry = std::make_unique<Dentry>(newname, src_inode);
	parent_inode->add_child(newname, new_dentry.get());

	memset(&e, 0, sizeof(e));
	e.ino = ino;
	e.attr_timeout = MEMFS_ATTR_TIMEOUT;
	e.entry_timeout = MEMFS_ENTRY_TIMEOUT;
	src_inode->get_attr(&e.attr);

out_unlock_parent:
	parent_inode->unlock();

out_unlock_global:
	Inodes.unlock();

	if (error == 0) {
		fuse_reply_entry(req, &e);
	} else {
		fuse_reply_err(req, error);
	}
}

static void memfs_statfs(fuse_req_t req, [[maybe_unused]] fuse_ino_t ino)
{
	struct statvfs stbuf;
	memset(&stbuf, 0, sizeof(stbuf));

	stbuf.f_bsize = 4096;
	stbuf.f_frsize = 4096;
	stbuf.f_namemax = PATH_MAX; // Maximum filename length

	stbuf.f_files = Inodes.size(); // Total inodes (files + directories)

	stbuf.f_ffree = std::numeric_limits<fsfilcnt_t>::max() -
			stbuf.f_files; // Free inodes

	// Set total and free blocks
	// For simplicity, we'll set a fixed total number of blocks and calculate free blocks based on used inodes
	stbuf.f_blocks = 1000000; // arbitrary number, needs to be a parameter
	stbuf.f_bfree = stbuf.f_blocks -
			(stbuf.f_files *
			 10); // Assume each file uses 10 blocks on average
	stbuf.f_bavail = stbuf.f_bfree;

	stbuf.f_fsid = 0;

	// Set flags
	stbuf.f_flag = ST_NOSUID;

	fuse_reply_statfs(req, &stbuf);
}

static const struct fuse_lowlevel_ops memfs_oper = {
	.init = nullptr,
	.destroy = nullptr,
	.lookup = memfs_lookup,
	.forget = memfs_forget,
	.getattr = memfs_getattr,
	.setattr = memfs_setattr,
	.readlink = nullptr,
	.mknod = nullptr,
	.mkdir = memfs_mkdir,
	.unlink = memfs_unlink,
	.rmdir = memfs_rmdir,
	.symlink = nullptr,
	.rename = memfs_rename,
	.link = memfs_link,
	.open = memfs_open,
	.read = memfs_read,
	.write = memfs_write,
	.flush = nullptr,
	.release = memfs_release,
	.fsync = nullptr,
	.opendir = memfs_opendir,
	.readdir = memfs_readdir,
	.releasedir = memfs_releasedir,
	.fsyncdir = nullptr,
	.statfs = memfs_statfs,
	.setxattr = nullptr,
	.getxattr = nullptr,
	.listxattr = nullptr,
	.removexattr = nullptr,
	.access = nullptr,
	.create = memfs_create,
	.getlk = nullptr,
	.setlk = nullptr,
	.bmap = nullptr,
	.ioctl = nullptr,
	.poll = nullptr,
	.write_buf = nullptr,
	.retrieve_reply = nullptr,
	.forget_multi = memfs_forget_multi,
	.flock = nullptr,
	.fallocate = nullptr,
	.readdirplus = nullptr,
	.copy_file_range = nullptr,
	.lseek = nullptr,
	.tmpfile = nullptr,
};

int main(int argc, char *argv[])
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	struct fuse_cmdline_opts opts;
	int ret = -1;
	struct fuse_loop_config *config = fuse_loop_cfg_create();

	if (config == NULL) {
		std::cerr << "fuse_loop_cfg_create failed" << std::endl;
		exit(EXIT_FAILURE);
	}

	if (fuse_parse_cmdline(&args, &opts) != 0)
		return 1;

	if (opts.show_help) {
		printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
		printf("File-system specific options:\n"
		       "    -o opt,[opt...]        mount options\n"
		       "    -h   --help            print help\n"
		       "\n");
		fuse_cmdline_help();
		fuse_lowlevel_help();
		ret = 0;
		goto err_out1;
	} else if (opts.show_version) {
		printf("FUSE library version %s\n", fuse_pkgversion());
		fuse_lowlevel_version();
		ret = 0;
		goto err_out1;
	}

	if (opts.mountpoint == NULL) {
		printf("usage: %s [options] <mountpoint>\n", argv[0]);
		printf("       %s --help\n", argv[0]);
		ret = 1;
		goto err_out1;
	}

	se = fuse_session_new(&args, &memfs_oper, sizeof(memfs_oper), NULL);
	if (se == NULL)
		goto err_out1;

	if (fuse_set_signal_handlers(se) != 0)
		goto err_out2;

	if (fuse_session_mount(se, opts.mountpoint) != 0)
		goto err_out3;

	fuse_daemonize(opts.foreground);

	ret = fuse_session_loop_mt(se, config);

	fuse_session_unmount(se);
err_out3:
	fuse_remove_signal_handlers(se);
err_out2:
	fuse_session_destroy(se);
err_out1:
	free(opts.mountpoint);
	fuse_opt_free_args(&args);

	return ret ? 1 : 0;
}

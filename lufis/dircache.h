/*
 * dircache.h
 * Copyright (C) 2002 Florin Malita <mali@go.ro>
 *
 * This file is part of LUFS, a free userspace filesystem implementation.
 * See http://lufs.sourceforge.net/ for updates.
 *
 * LUFS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * LUFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _DIRCACHE_H_
#define _DIRCACHE_H_

#include <fuse.h>

#ifdef __cplusplus
extern "C" {
#endif


#define NBUCKETS	7
#define DEF_NENTRIES	6
#define DEF_TTL		20

struct list_head;

struct direntry{
    char 		*e_name;
    char 		*e_link;
    struct list_head	e_list;
    struct lufs_fattr 	e_attr;
};

struct directory{
    char		*d_name;
    struct list_head	d_entries;
    struct list_head	d_list;
    unsigned long d_stamp;
};

struct dir_cache{
    int			ttl;
    int			entries;
    pthread_mutex_t	lock;
    struct list_head	buckets[NBUCKETS];
    int			lengths[NBUCKETS];
};

struct dir_cache* lu_cache_create(struct list_head*);
void lu_cache_destroy(struct dir_cache*);

int lu_cache_lookup_file(struct dir_cache*, char*, struct lufs_fattr*, char*, int);
void lu_cache_add(struct dir_cache*, char*, char*, struct lufs_fattr*, char*);
int lu_cache_readdir(struct dir_cache *cache, char *dir,
                     fuse_dirh_t h, fuse_dirfil_t filler);
int lu_cache_invalidate(struct dir_cache*, char*);


#ifdef __cplusplus
}
#endif

#endif

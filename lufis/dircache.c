/*
 * dircache.c
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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <sys/stat.h>

#include <lufs/proto.h>
#include <lufs/fs.h>

#include "list.h"
#include "dircache.h"

static char root_dir[]="/";
static char current_dir[]=".";

static unsigned long
hash(char *name){
    unsigned long res = 0;
    unsigned int i;

    for(i = 0; i < strlen(name); i++)
	if(name[i] != '/')
	    res = 0x21413 * (res + name[i]);
    
    return res % NBUCKETS;
}

static void
delete_dir(struct directory *d){
    struct list_head *p, *tmp;
    struct direntry *de;

    TRACE("in");
    list_for_each_safe(p, tmp, &d->d_entries){
	de = list_entry(p, struct direntry, e_list);
	list_del(&de->e_list);
	free(de->e_name);
	if(de->e_link)
	    free(de->e_link);
	free(de);
    }

    list_del(&d->d_list);
    free(d->d_name);
    free(d);

    TRACE("out");
}

struct dir_cache*
lu_cache_create(struct list_head *cfg){
    struct dir_cache *cache;
    int i;
    const char *c;

    TRACE("creating dir cache...");

    if(!(cache = malloc(sizeof(struct dir_cache))))
	return NULL;

    memset(cache, 0, sizeof(struct dir_cache));

    for(i = 0; i < NBUCKETS; i++)
	INIT_LIST_HEAD(&cache->buckets[i]);

    pthread_mutex_init(&cache->lock, NULL);
    
    cache->ttl = DEF_TTL;
    if((c = lu_opt_getchar(cfg, "LUFSD", "DirCacheTTL")) && atoi(c))
	cache->ttl = atoi(c);
    if((c = lu_opt_getchar(cfg, "MOUNT", "dir_cache_ttl")) && atoi(c))
	cache->ttl = atoi(c);
    
    cache->entries = DEF_NENTRIES;
    if((c = lu_opt_getchar(cfg, "LUFSD", "DirCacheEntries")) && atoi(c))
	cache->entries = atoi(c);
    if((c = lu_opt_getchar(cfg, "MOUNT", "dir_cache_entries")) && atoi(c))
	cache->entries = atoi(c);

    TRACE("entries: %d, ttl: %d", cache->entries, cache->ttl);

    return cache;
}

void
lu_cache_destroy(struct dir_cache *cache){
    struct list_head *p, *tmp;
    int i;
    
    for(i = 0; i < NBUCKETS; i++){
	list_for_each_safe(p, tmp, &cache->buckets[i]){
	    delete_dir(list_entry(p, struct directory, d_list));
        }
    }

    free(cache);
}

static struct directory*
search(struct dir_cache *cache, char *dir){
    struct list_head *p, *tmp;
    struct directory *d;
    int hsh;

    hsh = hash(dir);

    TRACE("search %s in bucket %u, size=%u", dir, hsh, cache->lengths[hsh]);

    list_for_each_safe(p, tmp, &cache->buckets[hsh]){
	d = list_entry(p, struct directory, d_list);
	
	if(time(NULL) - d->d_stamp >= (unsigned long) cache->ttl){
	    TRACE("%s expired...", d->d_name);
	    delete_dir(d);
	    cache->lengths[hsh]--;
	    TRACE("directory deleted");
	}else if(!strcmp(dir, d->d_name)){
	    TRACE("%s found", dir);
	    d->d_stamp = time(NULL);
	    return d;
	}
    }

    TRACE("dir not found");
    return NULL;
}

int
lu_cache_lookup(struct dir_cache *cache, char *dir, char *file, struct lufs_fattr *fattr, char *link, int buflen){
    struct directory *d;
    struct direntry *de;
    struct list_head *p;
    int res = -1;

    TRACE("looking up %s in dir %s", file, dir);

    pthread_mutex_lock(&cache->lock);

    if(!(d = search(cache, dir)))
	goto out;

    list_for_each(p, &d->d_entries){
	de = list_entry(p, struct direntry, e_list);
	if(!strcmp(file, de->e_name)){
	    TRACE("file found");

	    memcpy(fattr, &de->e_attr, sizeof(struct lufs_fattr));
	    if(link){
		if(de->e_link){
		    if(snprintf(link, buflen, "%s", de->e_link) >= buflen){
			WARN("link too long!");
			link[buflen - 1] =0;
		    }
		}else{
		    link[0] = 0;
		}
	    }
	    	    
	    res = 0;
	    goto out;
	}
    }

    TRACE("file not found!");

  out:
    pthread_mutex_unlock(&cache->lock);
    return res;
}

static void
shrink(struct dir_cache *cache, int hsh){
    struct directory *dir;

    TRACE("shrinking bucket %u, len=%u", hsh, cache->lengths[hsh]);

    if(list_empty(&cache->buckets[hsh]))
	return;

    dir = list_entry(cache->buckets[hsh].prev, struct directory, d_list);

    TRACE("deleting dir %s", dir->d_name);
    
    delete_dir(dir);
    cache->lengths[hsh]--;
}

static void
check_dir(struct directory *d){
    struct list_head *p, *tmp;
    struct direntry *e;
    struct lufs_fattr dummy;
    int dot = 0, dotdot = 0;

    memset(&dummy, 0, sizeof(struct lufs_fattr));
    dummy.f_nlink = 1;
    dummy.f_uid = dummy.f_gid = 1;
    dummy.f_mode = S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP;
    dummy.f_mtime = dummy.f_atime = dummy.f_ctime = time(NULL);
    dummy.f_size = 512;

    do{
	list_for_each_safe(p, tmp, &d->d_entries){
	    e = list_entry(p, struct direntry, e_list);
	    
	    if(!strcmp(e->e_name, ".")){
		TRACE("'.' entry found");
		list_del(&e->e_list);
		list_add(&e->e_list, &d->d_entries);
		dot = 1;
		continue;
	    }
	    
	    if(!strcmp(e->e_name, "..")){
		TRACE("'..' entry found");
		list_del(&e->e_list);
		if(!dot)
		    list_add(&e->e_list, &d->d_entries);
		else
		    list_add(&e->e_list, d->d_entries.next);
		
		dotdot = 1;
	    }
	}
	
	if(!dot)
	    lu_cache_add2dir(d, ".", NULL, &dummy);

	if(!dotdot)
	    lu_cache_add2dir(d, "..", NULL, &dummy);

    }while((!dot) || (!dotdot));

}

void
lu_cache_add_dir(struct dir_cache *cache, struct directory *d){
    struct directory *dir;
    int hsh;

    hsh = hash(d->d_name);

    TRACE("adding dir %s to bucket %i", d->d_name, hsh);
    
    check_dir(d);

    pthread_mutex_lock(&cache->lock);

    if((dir = search(cache, d->d_name))){
	TRACE("directory already in cache, deleting...");
	delete_dir(dir);
	cache->lengths[hsh]--;
    }

    d->d_stamp = time(NULL);

    list_add(&d->d_list, &cache->buckets[hsh]);
    cache->lengths[hsh]++;

    while(cache->lengths[hsh] > cache->entries)
	shrink(cache, hsh);

    pthread_mutex_unlock(&cache->lock);
    
    TRACE("out");
}

int lu_cache_readdir(struct dir_cache *cache, char *dir,
                     fuse_dirh_t h, fuse_dirfil_t filler)
{
    struct directory *d;
    struct direntry *de;
    struct list_head *p;
    int res = -1;

    TRACE("reading directory %s", dir);

    pthread_mutex_lock(&cache->lock);

    if(!(d = search(cache, dir)))
	goto out;
    
    list_for_each(p, &d->d_entries){
        de = list_entry(p, struct direntry, e_list);
#if FUSE_MAJOR_VERSION < 2 || (FUSE_MAJOR_VERSION == 2 && FUSE_MINOR_VERSION < 1)
        filler(h, de->e_name, 0);
#else
        filler(h, de->e_name, 0, 0);
#endif
    }

    d->d_stamp = time(NULL);

    res = 0;

  out:
    pthread_mutex_unlock(&cache->lock);
    TRACE("out");
    return res;
}

int
lu_cache_lookup_file(struct dir_cache *cache, char *file, struct lufs_fattr *fattr, char *link, int buflen){
    int res;

    char *sep, *dir;
    
    if(!(sep = strrchr(file, '/'))){
	WARN("separator not present!");
	return -1;
    }

    *sep = 0;

    if(sep == file)
	dir = root_dir;
    else
	dir = file;
    
    if(*(sep+1))
	file = sep + 1;
    else
	file = current_dir;

    TRACE("dir: %s, file: %s", dir, file);

    res = lu_cache_lookup(cache, dir, file, fattr, link, buflen);
    *sep = '/';

    return res;
}

int
lu_cache_invalidate(struct dir_cache *cache, char *file){
    struct directory *d;
    char *sep, *dir;

    if(!(sep = strrchr(file, '/'))){
	WARN("separator not present!");
	return -1;
    }

    *sep = 0;

    if(sep == file)
	dir = root_dir;
    else
	dir = file;
    
    TRACE("invalidating dir %s", dir);

    pthread_mutex_lock(&cache->lock);

    if(!(d = search(cache, dir))){
	*sep = '/';
	pthread_mutex_unlock(&cache->lock);
	return -1;
    }

    d->d_stamp = 0;

    pthread_mutex_unlock(&cache->lock);
    *sep = '/';
    
    return 0;
}

struct directory*
lu_cache_mkdir(char *dir){
    struct directory *res;

    TRACE("create dir %s", dir);

    if(!(res = malloc(sizeof(struct directory)))){
	WARN("out of mem!");
	return NULL;
    }

    memset(res, 0, sizeof(struct directory));

    if(!(res->d_name = malloc(strlen(dir) + 1))){
	WARN("out of mem!");
	free(res);
	return NULL;
    }

    INIT_LIST_HEAD(&res->d_entries);
    res->d_stamp = time(NULL);
    strcpy(res->d_name, dir);
    
    return res;
}

int
lu_cache_add2dir(struct directory *d, char *fname, char *link, struct lufs_fattr *fattr){
    struct direntry *de;

    TRACE("adding %s->%s to %s", fname, link, d->d_name);

    if(!(de = malloc(sizeof(struct direntry))))
	goto fail;


    if(!(de->e_name = malloc(strlen(fname) + 1)))
	goto fail_de;


    if(link)
	de->e_link = malloc(strlen(link) + 1);
    else
	de->e_link = malloc(2);
    
    if(!de->e_link)
	goto fail_ename;

    memcpy(&de->e_attr, fattr, sizeof(struct lufs_fattr));
    strcpy(de->e_name, fname);
    if(link)
	strcpy(de->e_link, link);
    else
	strcpy(de->e_link, "");

    list_add_tail(&de->e_list, &d->d_entries);    

    return 0;

  fail_ename:
    free(de->e_name);
  fail_de:
    free(de);
  fail:
    WARN("out of mem!");
    return -1;
}

void
lu_cache_killdir(struct directory *d){
    struct list_head *p, *tmp;
    struct direntry *de;

    TRACE("in");

    list_for_each_safe(p, tmp, &d->d_entries){
	de = list_entry(p, struct direntry, e_list);
	list_del(&de->e_list);
	free(de->e_name);
	if(de->e_link)
	    free(de->e_link);
	free(de);
    }

    free(d->d_name);
    free(d);

}

/*
 * options.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lufs/fs.h>

#include "list.h"

struct option {
    char *key;
    char *value;
    struct list_head list;
};

struct domain {
    char *name;
    struct list_head properties;
    struct list_head list;
};


static void
trim(char *buf){
    int b,e;
    
    if(!buf[0])
	return;

    for(b = 0; (buf[b] == ' ') || (buf[b] == '\t'); b++);
    for(e = strlen(buf) - 1; (e >= 0) && ((buf[e] == ' ') || (buf[e] == '\t')); e--);
    if(e < 0)
	e = strlen(buf) - 1;

    buf[e + 1] = 0;
    
    if(b)
	strcpy(buf, &buf[b]);

}

static struct domain*
find_domain(struct list_head *conf, char *name){
    struct list_head *p;
    struct domain *cls;

    list_for_each(p, conf){
	cls = list_entry(p, struct domain, list);
	if(!strcmp(name, cls->name)){
	    TRACE("domain found");
	    return cls;
	}
    }

    return NULL;
}

int
lu_opt_loadcfg(struct list_head *conf, char *file){
    struct domain *class;
    struct option *prop;
    FILE *f;
    static char buf[1024];
    char *i, *j;
    char *cls, *key, *val;

    TRACE("loading config from %s", file);

    if(!(f = fopen(file, "r"))){
	WARN("could not open file for reading!");
	return -1;
    }

    while(fgets(buf, 1024, f)){
	
	buf[strlen(buf) - 1] = 0;

	if((i = strchr(buf, '#')))
	    *i = 0;
	
	if((i = strchr(buf, '='))){
	    if((j = strstr(buf, "::"))){
		cls = buf;
		key = j + 2;
		val = i + 1;
		
		*i = 0;
		*j = 0;

		trim(cls);
		trim(key);
		trim(val);

		TRACE("class: #%s#", cls);
		TRACE("key: #%s#", key);
		TRACE("val: #%s#", val);

		if(!(class = find_domain(conf, cls))){
		    TRACE("class not found, creating...");

		    if(!(class = malloc(sizeof(struct domain)))){
			WARN("out of mem!");
			break;
		    }

		    memset(class, 0, sizeof(struct domain));

		    if(!(class->name = malloc(strlen(cls) + 1))){
			WARN("out of mem!");
			free(class);
			break;
		    }

		    strcpy(class->name, cls);
		    INIT_LIST_HEAD(&class->properties);

		    list_add(&class->list, conf);
		}

		if(!(prop = malloc(sizeof(struct option)))){
		    WARN("out of mem!");
		    break;
		}

		if(!(prop->key = malloc(strlen(key) + 1))){
		    WARN("out of mem!");
		    free(prop);
		    break;
		}

		if(!(prop->value = malloc(strlen(val) + 1))){
		    WARN("out of mem!");
		    free(prop->key);
		    free(prop);
		    break;
		}

		strcpy(prop->key, key);
		strcpy(prop->value, val);
		
		list_add(&prop->list, &class->properties);
	    }
	}
	
    }


    fclose(f);

    return 0;
}


const char*
lu_opt_getchar(struct list_head *conf, char *cls, char *key){
    struct domain *class;
    struct option *prop;
    struct list_head *p;

    TRACE("retrieving %s::%s", cls, key);
    
    if(!(class = find_domain(conf, cls)))
	return NULL;

    list_for_each(p, &class->properties){
	prop = list_entry(p, struct option, list);

	if(!strcmp(key, prop->key)){
	    TRACE("key found");
	    return prop->value;
	}
    }

    TRACE("key not found");

    return NULL;
}

int
lu_opt_getint(struct list_head *conf, char *domain, char *key, long int *result, int base){
    char *end;
    const char *val;
    long int res;

    if(!(val = lu_opt_getchar(conf, domain, key)))
	return -1;
    
    res = strtol(val, &end, base);
    
    if(*end)
	return -1;
    
    *result = res;
    return 0;
}

int
lu_opt_parse(struct list_head *conf, char *domain, char *opts){
    struct domain *class;
    struct option *prop;
    char *p, *sep;

    if(!(class = find_domain(conf, domain))){
	TRACE("domain not found, creating...");
	
	if(!(class = malloc(sizeof(struct domain)))){
	    WARN("out of mem!");
	    return -1;
	}
	
	memset(class, 0, sizeof(struct domain));
	
	if(!(class->name = malloc(strlen(domain) + 1))){
	    WARN("out of mem!");
	    free(class);
	    return -1;
	}
	
	strcpy(class->name, domain);
	INIT_LIST_HEAD(&class->properties);
	
	list_add(&class->list, conf);
    }
    
    for(p = strtok(opts, ","); p; p = strtok(NULL, ",")){
	if(!strstr(p, "password"))
	    TRACE("option: %s", p);

	if(!(prop = malloc(sizeof(struct option)))){
	    WARN("out of mem!");
	    return -1;
	}

	if((sep = strchr(p, '=')))
	    *sep = 0;

	if(!(prop->key = malloc(strlen(p) + 1))){
	    WARN("out of mem!");
	    free(prop);
	    return -1;
	}
	strcpy(prop->key, p);

	if(sep){
	    TRACE("option with parameter");

	    if(!(prop->value = malloc(strlen(sep + 1) + 1))){
		WARN("out of mem!");
		free(prop->key);
		free(prop);
		return -1;
	    }
	    strcpy(prop->value, sep + 1);
	    
	    if(strstr(p, "password")){
		TRACE("hiding password...");
		memset(sep + 1, ' ', strlen(sep + 1));
	    }
	}else{
	    TRACE("flag");

	    if(!(prop->value = malloc(2))){
		WARN("out of mem!");
		free(prop->key);
		free(prop);
		return -1;
	    }
	    strcpy(prop->value, "");
	    
	}

	list_add(&prop->list, &class->properties);

    }

    return 0;
}



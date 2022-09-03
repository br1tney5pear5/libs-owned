/*
 * The MIT License (MIT)
 *
 *  Copyright (c) Kacper Kokot
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

#ifndef _KK_MAP_H_
#define _KK_MAP_H_

#include "rbtree.h"

struct map {
  /* give it good locality allocator for nodes maybe */
  struct rbtree rbt;
};

struct _map_key {
  uint8_t hash[8];
  char *key;
};

struct _map_data {
  void *data;
};

int map_init(struct map *map);

int map_insert(struct map *map, const char *key, void *data);

void *map_search(struct map *map, const char *key);



#endif /* #ifndef _KK_MAP_H_ */

/* implemenatation */

#ifdef KK_MAP_IMPL

#define MAP_UNLIKELY(X) __builtin_expect((X),0)

int _map_key_init(struct _map_key *mkey, const char *str, bool local)
{
  size_t len = strlen(str);

  memset(mkey, 0, sizeof(*mkey));

  if(len > sizeof(mkey->hash)/sizeof(mkey->hash[0])) {
    if(local) {
      mkey->key = (char*)str; 
    } else {
      mkey->key = realloc(NULL, len + 1);
      if(!mkey->key)
        return -1;

      memcpy(mkey->key, str, len);
      mkey->key[len] = '\0';
    }

    memcpy(mkey->hash, mkey->key, sizeof(mkey->hash)/sizeof(mkey->hash[0]));
  } else {
    memcpy(mkey->hash, str, len);
  }

  return 0;
}

int _map_key_free(struct _map_key *mkey) 
{
  if(mkey->key) {
    if(realloc(mkey->key, 0)) { /* ignore realloc return value */ };
  }
}

static inline 
int _map_key_cmp(const void *_a, const void *_b) 
{
  const struct _map_key *a = _a;
  const struct _map_key *b = _b;

  int result = memcmp(a->hash, b->hash, 
      sizeof(a->hash)/sizeof(a->hash[0]));

  if(MAP_UNLIKELY(!result)) {
    if(a->key && b->key)
      return strcmp(a->key, b->key);
  }

  return result;
}

int map_init(struct map *map) 
{
  int ret = -1;
  if(rbtree_init(&map->rbt, 
        sizeof(struct _map_key),
        sizeof(struct _map_data), 
        _map_key_cmp, 
        realloc))
    goto exit;
    
  ret = 0;
exit:
  return ret;
}

int map_insert(struct map *map, const char *key, void *data) 
{
  int ret = -1;
  struct rbnode *rbn;
  struct _map_key mkey = {};

  if(_map_key_init(&mkey, key, false))
    goto exit;

  rbn = rbtree_insert(&map->rbt, &mkey);
  if(!rbn) 
    goto cleanup;

  struct _map_data *mdata = rbnode_get_data(&map->rbt, rbn);
  mdata->data = data;

  ret = 0;
  goto exit;
cleanup:
  _map_key_free(&mkey);
exit:
  return ret;
}

void *map_search(struct map *map, const char *key) 
{
  struct rbnode *rbn;
  struct _map_key mkey = {};

  if(_map_key_init(&mkey, key, true))
    return NULL;

  rbn = rbtree_search(&map->rbt, &mkey);
  if(!rbn) 
    return NULL;

  return ((struct _map_data*)rbnode_get_data(&map->rbt, rbn))->data;
}

#endif /* #ifdef KK_MAP_IMPL */

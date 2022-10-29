#ifndef _OPTS_H_
#define _OPTS_H_

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdio.h>
#include <assert.h>

#ifndef OPT_XALLOC
#define OPT_XALLOC(PTR, SZ) _default_opt_xalloc(PTR, SZ)
#endif



#define OPT_DEBUG(P, ...)\
  if((P)->config.debug_prints) {\
    fprintf(stderr, __VA_ARGS__);\
  } (void)0

enum {
  OPT_E_FAIL  = -1,
  OPT_E_OK    =  0,
  OPT_E_DONE  =  1,
};

enum {
  OPT_F_STRING            =   (1 << 0), 
  OPT_F_BOOLEAN           =   (1 << 1),
#if 0 /* not implemented */
  OPT_F_UNSIGNED          =   (1 << 2), 
  OPT_F_INTEGER           =   (1 << 3), 
  OPT_F_LONGLONG          =   (1 << 4), 
  OPT_F_FLOAT             =   (1 << 5),
#endif

#define OPT_TYPE_MASK (OPT_F_STRING | OPT_F_BOOLEAN)

  OPT_F_VARIADIC          =   (1 << 6),
#if 0 /* not implemented */
  OPT_F_REQUIRED          =   (1 << 7),
  OPT_F_DEFAULT           =   (1 << 8),
  OPT_F_RANGE             =   (1 << 9),
#endif
};

struct option {
  /* set by the user */
  char *name; 
  char short_name; 
  unsigned int flags;
  char *desc; 

  /* used internally */
  int index;

  int set;
  /* Lets say you have variadic option -a, and then pass the option 
   * multiple times like so: -a 1 2 -a 3 4 -b -a 5 6...
   *
   * Then, when parsing incrementally, you don't really know which 
   * params were just parsed and which ones are were passed previously.
   *
   * This parameters gives you offset to the currently passed parms. 
   * So in the above example, lets say, after second invocation of
   * do_parse_options_incrementally, the string_params would look like 
   * this [1,2,3,4] and the off_params would be 2, pointing to 3 and 4.
   */
  int off_params;
  int num_params;
  union {
    void      *params;    
    char     **string_params;
    int       *int_params;
    long long *long_long_params;
  };
  /* For OPT_F_RANGE flag */
  union {
    struct { int min, max; } int_range;
    struct { float min, max; } float_range;
  };
};

struct option_parser_config {
  bool custom;
  char *short_prefix;
  char *long_prefix;
  char *sentinel;
  char variadic_delimiter;
  bool allow_amalgamated_short_options;
  bool debug_prints;
};

static
struct option_parser_config _default_option_parser_config = {
  .custom = false,
  .short_prefix = "-",
  .long_prefix = "--",
  .sentinel = "--",
  .variadic_delimiter = ' ',
  .allow_amalgamated_short_options = true,
  .debug_prints = false,
};

#define options_for(OPT, OPTS)\
    for(struct option *OPT = OPTS; OPT->name; OPT++)

struct option_parser {
  bool initialised;

  int argc;
  char **argv;

  int index;
  struct option *current;

  unsigned int flags;
  struct option *options;
  struct option *invalid_option;

  /* Where we left off when parsing amalgamated short 
   * options */
  int amalgamated_off;
  char *amalgamated_arg;

  /* All of the allocated buffers to free up at the end */
  int num_buffers;
  void **buffers;

  /* User can set this up */
  struct option_parser_config config;
};

int parse_options_incrementally(
    struct option_parser *p, struct option *options, int argc, char **argv);

void print_options_help(FILE *out, struct option *options);

#endif /* _OPTS_H_ */

/* 
 * 
 * Implementation 
 *
 */

#ifdef OPTS_IMPL
static
void *_default_opt_xalloc(void *ptr, size_t sz)
{
  return (!sz ? (free(ptr), NULL) : (!ptr ? malloc(sz) : realloc(ptr, sz)));
}

char *unprefix_argument(char *arg, char *prefix)
{
  int arg_len = strlen(arg);
  int prefix_len = strlen(prefix);

  if(prefix_len > arg_len)
    return NULL;

  if(memcmp(arg, prefix, prefix_len))
    return NULL;

  return arg + prefix_len;
}

int validate_options(struct option *options)
{
  int ret = -1;

  options_for(opt, options) {
    switch(opt->flags & OPT_TYPE_MASK) {
      /* If no type set, default to string */
      case 0:
        opt->flags |= OPT_F_STRING;
        break;
      /* Valid option type combinations */
      case OPT_F_STRING:
      case OPT_F_BOOLEAN:
#if 0 
      case OPT_F_FLOAT:
      case OPT_F_INTEGER:
      case OPT_F_INTEGER | OPT_F_UNSIGNED:
      case OPT_F_LONGLONG:
      case OPT_F_LONGLONG | OPT_F_UNSIGNED:
#endif
        break;

      /* Invalid combination */
      default:
        goto out;
    }
  }

  ret = 0;
out:
  return ret;
}

int init_option_parser(
    struct option_parser *p, struct option *options, int argc, char **argv)
{
  int ret = -1;
  assert(!p->initialised);

  if(argc < 0)
    goto out;

  if(argc && !argv)
    goto out;

  if(!options)
    goto out;

  p->argc = argc;
  p->argv = argv;
  p->options = options;

  if(!p->config.custom)
    p->config = _default_option_parser_config;

  int count = 0;
  options_for(opt, options) {
    opt->index = count;
    count++;
  }
  p->invalid_option = options + count;

  if(validate_options(options))
    goto out;

  p->initialised = true;
  ret = 0;
out:
  return ret;
}


int cleanup_option_parser(struct option_parser *p)
{
  options_for(opt, p->options) {
    if(opt->params)
      OPT_XALLOC(opt->params, 0);
  }
  p->initialised = false;
}

struct option *find_short_option(struct option_parser *p, char arg)
{
  options_for(opt, p->options) {
    if(opt->short_name && opt->short_name == arg)
      return opt;
  }
  return NULL;
}

struct option *find_long_option(struct option_parser *p, char *arg)
{
  options_for(opt, p->options) {
    if(opt->name && strcmp(arg, opt->name))
      return opt;
  }
  return NULL;
}


/* 
 * Returns NULL if the string doesn't look like an option.
 * Returns p->invalid_option if it looks like an option
 * but is invalid.
 */
struct option *try_parse_option(struct option_parser *p, char *_arg)
{
  char *arg = NULL;
  struct option *opt = NULL;

  /* Try parse long option */
  arg = unprefix_argument(_arg, p->config.long_prefix);
  if(arg) {
    options_for(opt, p->options) {
      if(opt->name && !strcmp(arg, opt->name))
        return (opt->set += 1, opt);
    }
    opt = p->invalid_option;
  } 

  /* Try parse short option */
  arg = unprefix_argument(_arg, p->config.short_prefix);
  if(arg) {
    int len = strlen(arg);
    if(len == 0)
      return p->invalid_option;

    /* Easy case */
    if(len == 1) {
      opt = find_short_option(p, arg[0]); 
      if(opt)
        return (opt->set += 1, opt);
    } else {
      if(p->config.allow_amalgamated_short_options) {
        /* Quick check that all amalgamated options are 
         * valid options */
        for(int i = 0; i < strlen(arg); ++i) {
          opt = find_short_option(p, arg[i]); 
          if(!opt)
            return p->invalid_option;
        }
        p->amalgamated_arg = arg;
        p->amalgamated_off = 0;
        /* If succeeded, return the last of the amalgamated options;
         * the one that may accept arguments. */
        return opt;
      }
    }
    opt = p->invalid_option;
  }

  return opt;
}

#define OPTSBUF_APPEND(BUF, COUNT, TYPE, EL)\
  do {\
    int sz = ((COUNT) + 1) * sizeof(TYPE);\
    (BUF) = OPT_XALLOC((void*)(BUF), sz);\
    (BUF)[(COUNT)] = (EL);\
    (COUNT) += 1;\
  } while(0)

int try_parse_argument(struct option_parser *p, char *arg)
{
  int ret = -1;

  assert(p->current);
  struct option *opt = p->current;
  int prev_num_params = opt->num_params;

  /* If the variadic delimiter is not space we have to split 
   * it ourselves... */
  if((opt->flags & OPT_F_VARIADIC) && 
     !isspace(p->config.variadic_delimiter)) 
  {
    int start = 0;
    int len = strlen(arg);
    for(int i = 0; i < len + 1; ++i) {
      if(arg[i] == p->config.variadic_delimiter || arg[i] == '\0') 
      {
        int subarg_len = i - start;
        char *subarg = OPT_XALLOC(NULL, subarg_len + 1);
        memcpy(subarg, &arg[start], subarg_len);
        subarg[subarg_len] = '\0';
        OPTSBUF_APPEND(opt->string_params, opt->num_params, char*, subarg);
        OPTSBUF_APPEND(p->buffers, p->num_buffers, void*, subarg);
        start = i + 1;
      }
    }
    goto done;
  }

  if(opt->flags & OPT_F_STRING) {
    if(opt->flags & OPT_F_VARIADIC) {
#if 1
      OPTSBUF_APPEND(opt->string_params, opt->num_params, char*, arg);
#else
      int sz = (opt->num_params + 1) * sizeof(char *);
      opt->params = OPT_XALLOC(opt->params, sz);
      opt->string_params[opt->num_params] = arg;
      opt->num_params += 1;
#endif
    } else {
      int sz = 1 * sizeof(char *);
      opt->params = OPT_XALLOC(opt->params, sz);
      opt->string_params[0] = arg;
      opt->num_params = 1;
    }
    goto done;
  }
done:
  if(opt->num_params == prev_num_params)
    goto out;
  ret = 0;
out:
  return ret;
}


int do_parse_options_incrementally(struct option_parser *p)
{
  int ret = -1;
  char *arg;

  p->current = NULL;
amalgamated:
  /* So this loop parses amalgamated short options like -abc.
   * This is by far the most unelegant part of the code since
   * its initially triggered by try_parse_option. 
   */
  if(p->amalgamated_arg) {
    int len = strlen(arg);
    while(p->amalgamated_off < len) {
      struct option *opt = 
        find_short_option(p, p->amalgamated_arg[p->amalgamated_off]); 

      OPT_DEBUG(p, 
          "Parsing amalgamated option '%c' at index %d from '%s', got %s.\n", 
          p->amalgamated_arg[p->amalgamated_off], p->amalgamated_off, 
          p->amalgamated_arg, opt ? opt->name : NULL);

      p->amalgamated_off += 1;
      if(!opt)
        goto out;

      p->current = opt;
      p->current->off_params = p->current->num_params;
      opt->set += 1;

      if(p->amalgamated_off == len - 1) {
        /* If its the last one, go do normal parsing */
        assert(p->current);
        p->amalgamated_arg = NULL;
        goto again;
      }

      /* All in the middle options must not take arguments. TODO: This 
       * condition may not be sufficient */
      if(!(opt->flags & OPT_F_BOOLEAN))
        goto out;

      goto done;
    }
  }

  if(p->index >= p->argc) {
    ret = OPT_E_DONE; goto out;
  }

again:
  if(p->index >= p->argc)
    goto done;

  arg = p->argv[p->index];
  OPT_DEBUG(p, "arg='%s' index=%d current=%s\n", 
      arg, p->index, p->current ? p->current->name : NULL);
  p->index += 1;
  assert(arg);

  if(p->config.sentinel && !strcmp(arg, p->config.sentinel)) {
    p->index = p->argc;
    ret = p->current ? 1 : 0; goto done;
  }

  if(!p->current) {
    struct option *opt = try_parse_option(p, arg);

    OPT_DEBUG(p, "Parsing option(s): '%s', got '%s'\n", 
        arg, opt ? opt->name : NULL);

    if(!opt || opt == p->invalid_option)
      goto out;

    if(p->amalgamated_arg)
      goto amalgamated;

    p->current = opt;
    p->current->off_params = p->current->num_params;
    if(opt->flags & OPT_F_BOOLEAN)
      goto done;
    else
      goto again;
  } else {
    /* If we parse variadic arguments to an option and delimiter is space
     * we have to look out for the next option */
    if( (p->current->flags & OPT_F_VARIADIC) && 
        isspace(p->config.variadic_delimiter)) 
    {
      struct option *opt = try_parse_option(p, arg);
      if(opt == p->invalid_option) 
        goto out;

      if(opt) {
        /* Okay, we're done with variadic args 
         *
         * Unless we got amalgamated options, back off so we can 
         * reparse the option next time.
         *
         * If we did get amalgmated options, we skip to the next arg
         * so when the special case loop for amalgamated options above
         * is done, it can pick up where we left off as usual.
         */
        if(!p->amalgamated_arg)
          p->index -= 1;

        goto done;
      }
    }

    /* parse argument */
    if(try_parse_argument(p, arg))
      goto out;

    /* If variadic delimter is not space, this means variadic opts must be
     * passed one at a time like -a 1 -a 2 -a 3... */
    if((p->current->flags & OPT_F_VARIADIC) && 
        isspace(p->config.variadic_delimiter))
      goto again;
    else
      goto done;
  } 

done:
  if(ret != OPT_E_DONE) {
    assert(p->current);
  }
  if(p->current) {
    /* If isn't boolean, yet has no params, its an error */
    int set_params = p->current->num_params - p->current->off_params;
    if(set_params  == 0 && !(p->current->flags & OPT_F_BOOLEAN))
      goto out;
  }

  if(p->config.debug_prints) {
    struct option *opt = p->current;
    OPT_DEBUG(p, "Got option '%s' set=%d num_params=%d params=%p:", 
        opt->name, opt->set, opt->num_params, opt->string_params);

    for(int i = opt->off_params; i < opt->num_params; ++i)
      OPT_DEBUG(p, " '%s'", opt->string_params[i]);

    OPT_DEBUG(p, "\n");
  }

  ret = 0;
out:
  if(ret == OPT_E_DONE) {
    options_for(opt, p->options)
      opt->off_params = 0;
  }
  return ret;
}

#define option_arguments_for(I, OPT)\
  for(int I = (OPT)->off_params; I < (OPT)->num_params; ++I)




int parse_options_incrementally(
    struct option_parser *p, struct option *options, int argc, char **argv) 
{
  int ret = -1;
  assert(p);

  if(!p->initialised) {
    if(init_option_parser(p, options, argc, argv))
      goto out;
  }

  ret = do_parse_options_incrementally(p);
  if(ret == OPT_E_DONE)
    cleanup_option_parser(p);
out:
  return ret;
}

int print_option_desc(FILE *out, struct option *option, int indent, int limit)
{
  int left = limit - indent;
  int desc_len = strlen(option->desc);
  if(desc_len <= left)
    return fprintf(out, "%s", option->desc);

  const char *desc = option->desc;
  const char *c = desc;
  const char *brk = desc;
  while(*c) {
    int left = limit - indent;
    for(c; *c; ++c) {
      if(isspace(*c)) {
        if(indent + c - brk > left) {
          fprintf(out, "%.*s\n%*s", c - brk, brk, indent, "");
          brk = c + 1;
        }
      }
    }
    if(*c == '\0')
      fprintf(out, "%.*s", c - brk, brk);
  }
}

void print_options_help(FILE *out, struct option *options)
{
  int longest = 0;
  options_for(option, options) {
    if(option->name) {
      int len = strlen(option->name);
      if(len > longest)
        longest = len;
    }
  }
  /* Space between long opt and the description */
  longest += 2;

  options_for(option, options) {
    int line_len = 0;
    if(option->short_name)
      line_len += fprintf(out, "   -%c", option->short_name);
    else
      line_len += fprintf(out, "     ");

    if(option->name) {
      line_len += fprintf(out, "%c ", option->short_name ? ',' : ' ');
      line_len += fprintf(out, "--%-*s", longest, option->name);
    } else {
      line_len += fprintf(out, "%*s", longest + strlen(", --"), "");
    }

    if(option->desc) {
      print_option_desc(out, option, line_len, 80);
    }
    fprintf(out, "\n");
  }
}


#endif /* _IMPL_OPTS_ */

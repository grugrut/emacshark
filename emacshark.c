#include <emacs-module.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int plugin_is_GPL_compatible;

struct bpf_program fp;
char filter_exp[] = "";
bpf_u_int32 mask;
bpf_u_int32 net;

static emacs_value
Femacshark_init(emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  char *dev, errbuf[PCAP_ERRBUF_SIZE];

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    fprintf(stderr, "Could'nt find device: %s\n", errbuf);
    return env->intern(env, "nil");
  }
  printf("Device:%s\n", dev);

  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device: %s: %s\n", dev, errbuf);
    return env->intern(env, "nil");
  }

  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s", filter_exp, pcap_geterr(handle));
    return env->intern(env, "nil");
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s", filter_exp, pcap_geterr(handle));
    return env->intern(env, "nil");
  }

  return env->make_user_ptr(env, free, handle);
}

static emacs_value
Femacshark_get (emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  struct pcap_t *handle = env->get_user_ptr(env, args[0]);
  struct pcap_pkthdr header;
  const u_char *packet;

  packet = pcap_next(handle, &header);
  return env->make_integer(env, header.len);
}

static emacs_value
Femacshark_close (emacs_env *env, ptrdiff_t nargs, emacs_value args[], void *data)
{
  pcap_t *handle = env->get_user_ptr(env, args[0]);
  pcap_close(handle);
  return env->intern(env, "t");
}

/* Provide FEATURE to Emacs.  */
static void
provide (emacs_env *env, const char *feature)
{
  /* call 'provide' with FEATURE converted to a symbol */

  emacs_value Qfeat = env->intern (env, feature);
  emacs_value Qprovide = env->intern (env, "provide");
  emacs_value args[] = { Qfeat };

  env->funcall (env, Qprovide, 1, args);
}

/* Bind NAME to FUN.  */
static void
bind_function (emacs_env *env, const char *name, emacs_value Sfun)
{
  /* Set the function cell of the symbol named NAME to SFUN using
     the 'fset' function.  */

  /* Convert the strings to symbols by interning them */
  emacs_value Qfset = env->intern (env, "fset");
  emacs_value Qsym = env->intern (env, name);

  /* Prepare the arguments array */
  emacs_value args[] = { Qsym, Sfun };

  /* Make the call (2 == nb of arguments) */
  env->funcall (env, Qfset, 2, args);
}



int
emacs_module_init (struct emacs_runtime *ert)
{
  emacs_env *env = ert->get_environment (ert);

#define DEFUN(lsym, csym, amin, amax, doc, data)                        \
  bind_function (env, lsym,                                             \
                 env->make_function(env, amin, amax, csym, doc, data))

  DEFUN ("emacshark-init", Femacshark_init, 0, 0, "Init emacshark", NULL);
  DEFUN ("emacshark-get", Femacshark_get, 1, 1, "Get next packet", NULL);
  DEFUN ("emacshark-close", Femacshark_close, 1, 1, "Close emacshark", NULL);

#undef DEFUN

  provide (env, "emacshark");

  /* loaded successfully */
  return 0;
}

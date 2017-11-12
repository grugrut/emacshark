/*
  Copyright (c) 2017 grugrut.

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <emacs-module.h>

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

int plugin_is_GPL_compatible;

struct bpf_program fp;
char filter_exp[] = "";
bpf_u_int32 mask;
bpf_u_int32 net;

struct sniff_ethernet {
  u_char ether_dhost[6];
  u_char ether_shost[6];
  u_short ether_type;
};

struct sniff_ip {
  u_char ip_vhl;
  u_char ip_tos;
  u_short ip_len;
  u_short ip_id;
  u_short ip_off;
  u_char ip_tol;
  u_char ip_protocol;
  u_short ip_chksum;
  u_char ip_src[4];
  u_char ip_dst[4];
};

#define SIZE_ETHERNET 14

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
  struct pcap_pkthdr header;
  const u_char *packet;
  const struct sniff_ip *ip;
  pcap_t *handle = env->get_user_ptr(env, args[0]);
  if (env->non_local_exit_check(env) != emacs_funcall_exit_return) {
    return env->intern(env, "nil");
  }

  packet = pcap_next(handle, &header);
  if (header.len == 0) {
    return env->intern(env, "nil");
  }
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

  char str[40];
  int len = sprintf(str, "%d.%d.%d.%d -> %d.%d.%d.%d",
                    (ip)->ip_src[0], (ip)->ip_src[1],(ip)->ip_src[2],(ip)->ip_src[3],
                      (ip)->ip_dst[0], (ip)->ip_dst[1],(ip)->ip_dst[2],(ip)->ip_dst[3]);

  return env->make_string(env, str, len);

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

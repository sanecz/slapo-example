/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005-2014 The OpenLDAP Foundation.
 * Portions copyright 2004-2005 Symas Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#ifdef SLAPD_OVER_EXAMPLE

#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "slap.h"
#include "config.h"

#define DEFAULT_KEYTAB_PATH "/etc/krb5.keytab"

typedef struct example_data {
  char *principalattr;
  char *exampledomain;
  krb5_context context;
  char *addr;
  char *keytabpath;
  ldap_pvt_thread_mutex_t examplemutex;
} example_data;


static ConfigTable examplecfg[] = {
  { "ExampleDomain", "arg", 2, 2, 0,
    ARG_STRING|ARG_OFFSET, (void *)offsetof(example_data, exampledomain),
    "( OLcfgCtAt:24.1 NAME 'ExampleDomain' "
    "DESC 'Example domain' "
    "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL},
  { "PrincipalAttr", "arg", 2, 2, 0,
    ARG_STRING|ARG_OFFSET, (void *)offsetof(example_data, principalattr),
    "( OLcfgCtAt:24.2 NAME 'PrincipalAttr' "
    "DESC 'Principal Attr' "
    "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
  { "ExampleHost", "arg", 2, 2, 0,
    ARG_STRING|ARG_OFFSET, (void *)offsetof(example_data, addr),
    "( OLcfgCtAt:24.3 NAME 'ExampleHost' "
    "DESC 'Hostname or IP address' "
    "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL},
  { "KeytabPath", "arg", 2, 2, 0,
    ARG_STRING|ARG_OFFSET, (void *)offsetof(example_data, keytabpath),
    "( OLcfgCtAt:24.4 NAME 'KeytabPath' "
    "DESC 'Path of the keytab' "
    "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL},
  { NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs exampleocs[] = {
  { "( OLcfgOvOc:24.1 "
    "NAME 'olcExampleConfig' "
    "DESC 'Example overlay' "
    "SUP olcOverlayConfig "
    "MAY ( KeytabPath ) "
    "MUST ( ExampleDomain $ PrincipalAttr $ ExampleHost ) ) ",
    Cft_Overlay, examplecfg},
  {NULL, 0, NULL}
};

static slap_overinst example;

static int example_init(BackendDB *be, ConfigReply *cr) {
  slap_overinst *on = (slap_overinst *)be->bd_info;
  example_data *ex = ch_calloc(1, sizeof(example_data));
  (void)cr;

  on->on_bi.bi_private = ex;
  return LDAP_SUCCESS;
}

static int example_open(BackendDB *be, ConfigReply *cr) {
  slap_overinst *on = (slap_overinst *)be->bd_info;
  example_data *ex = on->on_bi.bi_private;
  ObjectClass *oc_kerberos;
  
  ldap_pvt_thread_mutex_init(&ex->examplemutex);
  //  if (krb5_init_context(&ex->context)) return -1;

  oc_kerberos = oc_find("krbPrincipal");
  if (!oc_kerberos) return -1;

  if (!ex->keytabpath) ex->keytabpath = DEFAULT_KEYTAB_PATH;

  return 0;
}

static int example_destroy(BackendDB *be, ConfigReply *cr) {
  slap_overinst *on = (slap_overinst *)be->bd_info;
  example_data *ex = on->on_bi.bi_private;
  (void)cr;

  ldap_pvt_thread_mutex_destroy(&ex->examplemutex);
  free(ex);
  return LDAP_SUCCESS;
}

static int example_delete(Operation *op, SlapReply *rs) {
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
  (void)rs;
  
  return SLAP_CB_CONTINUE;
}

static int example_add(Operation *op, SlapReply *rs) {
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
  (void)rs;

  return SLAP_CB_CONTINUE;
}

static int example_callback(Operation *op, SlapReply *rs) {
  example_data* ex = op->o_callback->sc_private;
  Entry *entry = NULL;

  if (rs->sr_type != REP_SEARCH) return 0;

  if (rs->sr_entry) {
    entry = rs->sr_entry;
    Attribute *attr = NULL;
    for (attr = entry->e_attrs; attr; attr = attr->a_next) {
      if (!strcmp(attr->a_desc->ad_cname.bv_val, ex->principalattr)){
	if (attr->a_numvals > 0)  {
	  char *tmp = attr->a_vals[0].bv_val;
	  printf("%s: %s\n", example.on_bi.bi_type, tmp);
	}
      }
    }
  }

  return SLAP_CB_CONTINUE;
}

static int example_search(Operation *op, char *attrcontent) {
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
  example_data *ex = on->on_bi.bi_private;
  Operation nop = *op;
  slap_callback cb = { NULL, example_callback, NULL, NULL, ex};
  SlapReply nrs = { REP_RESULT };
  int rc;
  Filter *filter = NULL;
  struct berval fstr = BER_BVNULL;
  char *buffer;
  size_t len;

  len = strlen(ex->principalattr) + 5;
  buffer = (char *)malloc(sizeof(char) * len);
  if (!buffer) {
    nop.o_bd->bd_info = (BackendInfo *)(on->on_info);
    send_ldap_error(&nop, &nrs, LDAP_OTHER,
		    "Cannot allocate memory in example_search()");
    return nrs.sr_err;
  }
  snprintf(buffer, len, "(krbPrincipalName=%s@%s)", attrcontent, ex->exampledomain) ;
  filter = str2filter(buffer);
  filter2bv(filter, &fstr);

  nop.o_callback = &cb;
  op->o_bd->bd_info = (BackendInfo *) on->on_info;
  nop.o_tag = LDAP_REQ_SEARCH;
  nop.o_ctrls = NULL;
  nop.ors_scope = LDAP_SCOPE_SUBTREE;
  nop.ors_deref = LDAP_DEREF_NEVER;
  nop.ors_slimit = SLAP_NO_LIMIT;
  nop.ors_tlimit = SLAP_NO_LIMIT;
  nop.ors_attrsonly = 1;
  nop.ors_attrs = slap_anlist_no_attrs;
  nop.ors_filter = filter;
  nop.ors_filterstr = fstr;

  if (nop.o_bd->be_search) rc = nop.o_bd->be_search(&nop, &nrs);
  free(buffer);
  if (filter) filter_free(filter);
  if (fstr.bv_val) ch_free(fstr.bv_val);

  return SLAP_CB_CONTINUE;
}

static int example_response(Operation *op, SlapReply *rs) {
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
  example_data *ex = on->on_bi.bi_private;
  Attribute *a;

  if (rs->sr_err != LDAP_SUCCESS) return SLAP_CB_CONTINUE;

  if (!ex->exampledomain | !ex->principalattr) return SLAP_CB_CONTINUE;

  switch(op->o_tag) {
  case LDAP_REQ_MODRDN: printf("ldap req modrdn case\n"); break;
  case LDAP_REQ_DELETE: printf("ldap req delete case\n"); break;
  case LDAP_REQ_MODIFY: printf("ldap req modify case\n"); break;
  case LDAP_REQ_ADD:
    for (a = op->ora_e->e_attrs; a; a = a->a_next)
      if (!strcmp(a->a_desc->ad_cname.bv_val, ex->principalattr))
	printf("%s\n", a->a_vals[0].bv_val);
	example_search(op, a->a_vals[0].bv_val);
    break;
  default:
    printf("default case\n");
  }

  return SLAP_CB_CONTINUE;
}

int example_initialize() {
  int rc;

  example.on_bi.bi_type = "example";
  example.on_bi.bi_db_init = example_init;
  example.on_bi.bi_db_open = example_open;
  example.on_bi.bi_db_destroy = example_destroy;
  example.on_bi.bi_op_delete = example_delete;
  example.on_bi.bi_op_add = example_add;
  example.on_response = example_response;

  rc = config_register_schema(examplecfg, exampleocs);
  if (rc) return rc;

  return overlay_register(&example);
}

#if SLAPD_OVER_EXAMPLE == SLAPD_MOD_DYNAMIC

int init_module(int argc, char **argv) {
  (void)argc;
  (void)argv;
  return example_initialize();
}
#endif

#endif

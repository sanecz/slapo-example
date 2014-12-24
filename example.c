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

#include <stdio.h>
#include "slap.h"
#include "config.h"

typedef struct example_data {
  char *principalattr;
  char *exampledomain;
} example_data;


static ConfigTable examplecfg[] = {
  { "ExampleDomain", "arg", 2, 2, 0,
    ARG_STRING|ARG_OFFSET, (void *)offsetof(example_data, principalattr),
    "( OLcfgCtAt:24.1 NAME 'ExampleDomain' "
    "DESC 'Example domain' "
    "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL},
  { "PrincipalAttr", "arg", 2, 2, 0,
    ARG_STRING|ARG_OFFSET, (void *)offsetof(example_data, exampledomain),
    "( OLcfgCtAt:24.2 NAME 'PrincipalAttr' "
    "DESC 'Principal Attr' "
    "SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
  { NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs exampleocs[] = {
  { "( OLcfgOvOc:24.1 "
    "NAME 'olcExampleConfig' "
    "DESC 'Example overlay' "
    "SUP olcOverlayConfig "
    "MUST ( ExampleDomain $ PrincipalAttr ) )",
    Cft_Overlay, examplecfg},
  {NULL, 0, NULL}
};

static slap_overinst example;

static int example_init(BackendDB *be, ConfigReply *cr) {
  slap_overinst *on = (slap_overinst *)be->bd_info;
  example_data *ex = ch_calloc(1, sizeof(example_data));

  on->on_bi.bi_private = ex;
  printf("EXAMPLE| start success\n");
  return LDAP_SUCCESS;
}

static int example_destroy(BackendDB *be, ConfigReply *cr) {
  slap_overinst *on = (slap_overinst *)be->bd_info;
  example_data *ex = on->on_bi.bi_private;

  free(ex);
  printf("EXAMPLE| end success\n");
  return LDAP_SUCCESS;
}

static int example_delete(Operation *op, SlapReply *rs) {
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;

  return SLAP_CB_CONTINUE;
}

static int example_add(Operation *op, SlapReply *rs) {
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;

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
    printf("ldap req add case\n");
    for(a = op->ora_e->e_attrs; a; a = a->a_next) {
      printf("%s: %s\n", a->a_desc->ad_cname.bv_val, a->a_vals->bv_val);
    }
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
  return example_initialize();
}
#endif

#endif

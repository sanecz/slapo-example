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

static slap_overinst example;

static int example_init(BackendDB *be, ConfigReply *cr) {
  printf("EXAMPLE| start success\n");
  return 0;
}

static int example_destroy(BackendDB *be, ConfigReply *cr) {
  printf("EXAMPLE| end success\n");
  return LDAP_SUCCESS;
}

int example_initialize() {
  example.on_bi.bi_type = "example";
  example.on_bi.bi_db_init = example_init;
  example.on_bi.bi_db_destroy = example_destroy;

  return overlay_register(&example);
}

#if SLAPD_OVER_EXAMPLE == SLAPD_MOD_DYNAMIC

int init_module(int argc, char **argv) {
  return example_initialize();
}
#endif

#endif

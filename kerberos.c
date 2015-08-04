#include <kadm5/admin.h>
#include <krb5.h>
#include <string.h>

int init(krb5_context *context, void **handle,
	 char *keytab_name, char *princstr,
	 char *def_realm) {
  kadm5_ret_t retval;
  krb5_principal princ = NULL;
  kadm5_config_params params;
  char **db_args = NULL;
  int err = 0;
  
  memset(&params, 0, sizeof(params));
  params.mask |= KADM5_CONFIG_REALM;
  params.realm = def_realm;

  retval = kadm5_init_krb5_context(context);
  if (retval) {
    err = -1;
    com_err("kadm5_init_krb5_context()", retval, ".");
    goto cleanup;
  }
  retval = kadm5_init_with_skey(*context, princstr, keytab_name,
				NULL, &params,
				KADM5_STRUCT_VERSION,
				KADM5_API_VERSION_4,
				db_args,
				handle);
  if (retval) {
    err = -1;
    com_err("kadm5_init_with_skey()", retval, ".");
    goto cleanup;
  }

 cleanup:
  krb5_free_principal(*context, princ);
  return err;
}


int delprinc(krb5_context context, void *handle, char *user) {
  krb5_error_code retval;
  krb5_principal princ;
  int err = 0;
  
  retval = krb5_parse_name(context, user, &princ);
  if (retval) {
    err = -1;
    com_err("krb5_parse_name()", retval, ".");
    goto cleanup;
  }
  retval = kadm5_delete_principal(handle, princ);
  if (retval) {
    err = -1;
    com_err("kadm5_delete_principal()", retval, ".");
    goto cleanup;
  }
  
 cleanup:
  krb5_free_principal(context, princ);
  return err;
}

int addprinc(krb5_context context, void *handle, char *user, char *pass) {
  kadm5_principal_ent_rec princ;
  long mask = 0;
  krb5_error_code retval;
  int err = 0;
  
  memset(&princ, 0, sizeof(princ));
  princ.attributes = 0;

  retval = krb5_parse_name(context, user, &(princ.principal));
  if (retval) {
    err = -1;
    com_err("krb5_parse_name()", retval, ".");
    goto cleanup;
  }
  princ.policy = "default";
  
  mask |= KADM5_POLICY;
  mask &= ~KADM5_POLICY_CLR;
  mask |= KADM5_PRINCIPAL;

  retval = kadm5_create_principal(handle, &princ, mask, pass);
  if (retval) {
    err = -1;
    com_err("kadm5_create_principal()", retval, ".");
    goto cleanup;
  }

  princ.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
  mask = KADM5_ATTRIBUTES;
  
  retval = kadm5_modify_principal(handle, &princ, mask);
  if (retval) {
    err = -1;
    com_err("kadm5_modify_principal()", retval, ".");
    goto cleanup;
  }

 cleanup:
  krb5_free_principal(context, princ.principal);
  return err;
}

int main(void) {
  krb5_context context;
  void *handle = NULL;
  
  if (init(&context, &handle, "/tmp/test.keytab", "test/admin", "LYTCHI.LOCAL") != -1) {
    addprinc(context, handle, "titi", "pass");
    delprinc(context, handle, "titi");
  }
  kadm5_unlock(handle);
  kadm5_destroy(handle);
  krb5_free_context(context);
  return 0; 
}

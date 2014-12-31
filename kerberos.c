#include <string.h>
#include <krb5.h>
#include <kadm5/admin.h>

#define KEYTAB_DEFAULT_PATH "/etc/admin.keytab" 

void *handle = NULL;
krb5_context context;
char *ccache_name = NULL;
char *def_realm = NULL;
char *whoami = "example";
char *keytab_name = KEYTAB_DEFAULT_PATH;

int init() {
  kadm5_ret_t retval;
  krb5_ccache cc;
  krb5_principal princ;
  char *princstr = NULL;
  kadm5_config_params params;

  memset(&params, 0, sizeof(params));

  params.admin_server = "172.16.2.227:88";
  params.mask |= KADM5_CONFIG_ADMIN_SERVER;

  if ((retval = kadm5_init_krb5_context(&context))) {
    com_err(whoami, retval, "while initializing krb5 library", whoami);
    goto cleanup;
  }

  if ((retval = krb5_get_default_realm(context, &def_realm))) {
    fprintf(stderr, "%s: unable to get default realm\n", whoami);
    goto cleanup;
  }

  params.mask |= KADM5_CONFIG_REALM;
  params.realm = def_realm;
  
  if ((retval = krb5_cc_default(context, &cc))) {
    com_err(whoami, retval, "while opening default credentials cache");
    goto cleanup;
  }

  if ((retval = krb5_cc_get_principal(context, cc, &princ))) {
    com_err(whoami, retval, "while retrieving principal name");
    goto cc_cleanup;
  }

  if ((retval = krb5_unparse_name(context, princ, &princstr))) {
    com_err(whoami, retval, "while canonicalizing principal name");
    goto princ_cleanup;
  }

  retval = kadm5_init_with_skey(context, princstr, keytab_name, KADM5_ADMIN_SERVICE,
				&params, KADM5_STRUCT_VERSION,
				KADM5_API_VERSION_3, NULL, &handle);

  if (retval) {
    com_err(whoami, retval, "while initializing %s interface", whoami);
    goto princ_cleanup;
  }

 princ_cleanup:
  krb5_free_principal(context, princ);

 cc_cleanup:
  if ((retval = krb5_cc_close(context, cc)))
    com_err(whoami, retval, "while closing ccache %s", ccache_name);

 cleanup:
  free(princstr);

  return 0;
}


int destroy() {
  kadm5_ret_t retval;

  retval = kadm5_unlock(handle);
  kadm5_destroy(handle);
  krb5_klog_close(context);
  krb5_free_context(context);

  return 0;
}

int main() {
  init();
  destroy();

  return 0;
}

/*
Copyright 2021 Leibniz Institute for Psychology

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>

/* for LOG_* constants */
#include <syslog.h>

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>

/* Required for simple auth */
#define LDAP_DEPRECATED 1
#include <ldap.h>

#define __unused__ __attribute__((unused))

// XXX: drop privs using pam_modutil_drop_priv?

static const char * const acceptedAttribute = "x-acceptedTermsEffective";
/* See https://datatracker.ietf.org/doc/html/rfc4517#section-3.3.13 */
static const char * const generalizedTimeZero = "000000000000Z";

typedef struct {
	char *effective, *kind, *language, *content;
} terms_t;

typedef struct {
	char *baseDn, *userDnFormat, *ldapUri, *bindDn, *bindPassword;
} config_t;

/*	Destroy terms_t structure
 */
void termsFree (terms_t * const t) {
	free (t->effective);
	free (t->kind);
	free (t->language);
	free (t->content);
}

void configFree (config_t * const c) {
	free (c->baseDn);
	free (c->userDnFormat);
	free (c->ldapUri);
	free (c->bindDn);
	free (c->bindPassword);
}

int ldapOpen (const config_t * const config, pam_handle_t *pamh, LDAP **retLdap) {
	LDAP *ldap = NULL;
	*retLdap = NULL;

	int ret = ldap_initialize (&ldap, config->ldapUri);
	if (ret != LDAP_SUCCESS) {
		return PAM_SERVICE_ERR;
	}
	/* defaults to 2 */
	int protoVersion = 3;
	ldap_set_option (ldap, LDAP_OPT_PROTOCOL_VERSION, &protoVersion);
	ret = ldap_simple_bind_s (ldap, config->bindDn, config->bindPassword);
	if (ret != LDAP_SUCCESS) {
		pam_syslog (pamh, LOG_ERR, "bind to %s at %s failed %s",
				config->bindDn, config->ldapUri, ldap_err2string (ret));
		return PAM_SERVICE_ERR;
	}

	*retLdap = ldap;
	return PAM_SUCCESS;
}

int ldapClose (LDAP *ldap) {
	if (ldap != NULL) {
		ldap_unbind_s (ldap);
	}

	return PAM_SUCCESS;
}

/*	Copy the first result of an attribute and return it.
 */
char *dupFirstValue (LDAP * const ldap, LDAPMessage * const entry, const char * const key) {
	char *ret = NULL;

	char **vals = ldap_get_values (ldap, entry, key);
	if (vals != NULL) {
		if (*vals != NULL) {
			ret = strdup (*vals);
		}
		ldap_value_free (vals);
	}

	return ret;
}

/* Get all terms
 */
int getTerms (const config_t * const config, pam_handle_t *pamh, LDAP * const ldap, terms_t **retTerms, size_t *retNterms) {
	int ret = PAM_SUCCESS;

	*retTerms = NULL;
	*retNterms = 0;

	void *ALL_ATTRIBUTES = NULL;
	struct timeval timeout = { .tv_sec = 60 };
	LDAPMessage *res = NULL;
	char * const filter = "(&(objectClass=x-termsAndConditions))";
	ret = ldap_search_ext_s	(ldap, config->baseDn, LDAP_SCOPE_ONELEVEL, filter,
			ALL_ATTRIBUTES, 0, NULL, NULL, &timeout, 1000, &res);
	if (ret != LDAP_SUCCESS) {
		pam_syslog (pamh, LOG_ERR, "cannot get terms at %s with filter %s: %s",
				config->baseDn, filter, ldap_err2string (ret));
		ret = PAM_SERVICE_ERR;
		goto finalize;
	}
	int nentries = ldap_count_entries (ldap, res);
	if (nentries < 0) {
		ret = PAM_SERVICE_ERR;
		goto finalize;
	}
	terms_t * const terms = calloc (nentries+1, sizeof (*terms));
	LDAPMessage *entry = NULL;
	int i = 0;
	for (entry = ldap_first_entry (ldap, res), i = 0;
			i < nentries;
			i++, entry = ldap_next_entry (ldap, entry)) {
		terms_t * const t = &terms[i];
		t->effective = dupFirstValue (ldap, entry, "x-termsEffective");
		t->kind = dupFirstValue (ldap, entry, "x-termsKind");
		t->language = dupFirstValue (ldap, entry, "x-termsLanguage");
		t->content = dupFirstValue (ldap, entry, "x-termsContent");
	}
	*retTerms = terms;
	*retNterms = nentries;

finalize:
	if (res != NULL) {
		ldap_msgfree (res);
	}
	return ret;
}

bool formatUserDn (const config_t * const config, const char * const user, char *dn, int size) {
	return snprintf (dn, size, config->userDnFormat, user) < size;
}

/*	Check which version the user agreed to. Returns PAM_SUCCESS and NULL if the
 *	user is not a signatory */
int getUserAgreed (const config_t * const config, pam_handle_t *pamh, LDAP * const ldap, const char * const user, char **result) {
	*result = NULL;

	char dn[1024];
	if (!formatUserDn (config, user, dn, sizeof (dn))) {
		pam_syslog (pamh, LOG_ERR, "DN was too truncated %s", dn);
		return PAM_SERVICE_ERR;
	}

	char *attrs[] = {(char *) acceptedAttribute, NULL};
	struct timeval timeout = { .tv_sec = 60 };
	LDAPMessage *res = NULL;
	char *filter = "(&(objectclass=x-signatory))";
	int ret = ldap_search_ext_s	(ldap, dn, LDAP_SCOPE_BASE, filter, attrs, 0,
			NULL, NULL, &timeout, 1, &res);
	if (ret != LDAP_SUCCESS) {
		pam_syslog (pamh, LOG_ERR, "search failed %s", ldap_err2string (ret));
		ret = PAM_SERVICE_ERR;
		goto finalize;
	}

	int nentries = ldap_count_entries (ldap, res);
	if (nentries < 0) {
		ret = PAM_SERVICE_ERR;
		goto finalize;
	}
	if (nentries == 0) {
		pam_syslog (pamh, LOG_DEBUG, "user '%s' does not exist or is not signatory", user);
		ret = PAM_SUCCESS;
		goto finalize;
	}

	char *agreed = dupFirstValue (ldap, res, acceptedAttribute);
	if (agreed != NULL) {
		*result = agreed;
	} else {
		*result = strdup (generalizedTimeZero);
	}
	ret = PAM_SUCCESS;

finalize:
	if (res != NULL) {
		ldap_msgfree (res);
	}

	return PAM_SUCCESS;
}

int setUserAgreed (const config_t * const config, pam_handle_t * const pamh, LDAP * const ldap, const char * const user, char *value) {
	char dn[1024];
	if (!formatUserDn (config, user, dn, sizeof (dn))) {
		pam_syslog (pamh, LOG_ERR, "DN was too truncated %s", dn);
		return PAM_SERVICE_ERR;
	}
	
	char *val[] = {value, NULL};
	LDAPMod m = {
			.mod_op = LDAP_MOD_REPLACE,
			.mod_type = (char *) acceptedAttribute,
			.mod_vals = { .modv_strvals = val },
			};
	LDAPMod *mods[] = {&m, NULL};
	int ret = ldap_modify_ext_s (ldap, dn, mods, NULL, NULL);
	if (ret != LDAP_SUCCESS) {
		pam_syslog (pamh, LOG_ERR, "cannot set user has agreed: %s", ldap_err2string (ret));
		/* The failure is not bad enough to not let the user in. Worst case is
		 * we’ll have to query again. */
		return PAM_SUCCESS;
	} else {
		return PAM_SUCCESS;
	}
}

int askUserForAgreement (pam_handle_t *pamh, bool * const result) {
	*result = false;

	const struct pam_conv *conv = NULL;
	if (pam_get_item (pamh, PAM_CONV, (const void **) &conv) != PAM_SUCCESS) {
		return PAM_SERVICE_ERR;
	}

	struct pam_message msgs[10], *msg = &msgs[0], *pmsgs[10];
	int nmsg = 0;
	msg->msg = "Do you agree to the terms and conditions? [yn] ";
	msg->msg_style = PAM_PROMPT_ECHO_ON;
	pmsgs[nmsg] = msg;
	++msg;
	++nmsg;

	struct pam_response *resp = NULL;
	if (conv->conv (nmsg, (const struct pam_message **) pmsgs, &resp, conv->appdata_ptr) != PAM_SUCCESS || resp == NULL) {
		return PAM_CONV_ERR;
	}

	const char * const agreedStr = resp[nmsg-1].resp;
	const bool agreed = *result = strcmp (agreedStr, "y") == 0;
	if (agreed) {
		pam_syslog (pamh, LOG_DEBUG, "user agreed to tos");
	}

	return PAM_SUCCESS;
}

int readConfig (pam_handle_t * const pamh, const char * const configFile, config_t * const config) {
	FILE *fd = NULL;
	if ((fd = fopen (configFile, "r")) == NULL) {
		pam_syslog(pamh, LOG_ERR, "cannot open config file %s", configFile);
		return PAM_SERVICE_ERR;
	}

	char *line = NULL;
	size_t n = 0;
	while (getline (&line, &n, fd) != -1) {
		char *next = line;
		char *key = strsep (&next, "\t ");
		char *value = strsep (&next, "\n");
		if (strcmp (key, "baseDn") == 0) {
			config->baseDn = strdup (value);
		} else if (strcmp (key, "userDnFormat") == 0) {
			config->userDnFormat = strdup (value);
		} else if (strcmp (key, "ldapUri") == 0) {
			config->ldapUri = strdup (value);
		} else if (strcmp (key, "bindDn") == 0) {
			config->bindDn = strdup (value);
		} else if (strcmp (key, "bindPassword") == 0) {
			config->bindPassword = strdup (value);
		} else {
			pam_syslog (pamh, LOG_ERR, "ignoring config unknown option %s=%s", key, value);
		}
	}
	free (line);
	fclose (fd);
	return PAM_SUCCESS;
}

/*	Session entry point
 */
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags __unused__,
		int argc, const char **argv) {
	int ret = PAM_IGNORE;
	/* these must be defined on top, in order for the finalize to work */
	config_t config = { NULL, NULL, NULL, NULL, NULL};
	LDAP *ldap = NULL;
	terms_t *terms = NULL;
	size_t nterms = 0;

	/* get configuration file name from opts */
	char const *configFile = NULL;
	for (int i = 0; i < argc; i++) {
		const char *str = argv[i];
		if (strncmp ("config=", str, 7) == 0) {
			str = &str[7];
			if (strlen (str) > 0) {
				configFile = str;
			}
		} else {
			pam_syslog(pamh, LOG_ERR, "unknown option: %s", *argv);
		}
	}
	if (configFile == NULL) {
		pam_syslog(pamh, LOG_ERR, "config option missing");
		return PAM_SERVICE_ERR;
	}

	if ((ret = readConfig (pamh, configFile, &config)) != PAM_SUCCESS) {
		goto finalize;
	}

    const char *user = NULL;
    if (pam_get_user (pamh, &user, NULL) != PAM_SUCCESS) {
		return PAM_USER_UNKNOWN;
    }

	if ((ret = ldapOpen (&config, pamh, &ldap)) != PAM_SUCCESS) {
		goto finalize;
	}

	/* get the current terms */
	if ((ret = getTerms (&config, pamh, ldap, &terms, &nterms)) != PAM_SUCCESS) {
		goto finalize;
	}
	if (nterms == 0) {
		/* nothing to agree on */
		pam_syslog (pamh, LOG_DEBUG, "no terms exist");
		goto finalize;
	}
	/* check which version the user agreed to */
	const char *agreedVersion = NULL;
	if ((ret = getUserAgreed (&config, pamh, ldap, user, (char **) &agreedVersion)) != PAM_SUCCESS) {
		goto finalize;
	}
	if (agreedVersion == NULL) {
		/* not a signatory, he can pass */
		ret = PAM_SUCCESS;
		goto finalize;
	}

	/* make sure the user agreed to the latest one */
	bool agreed = true;
	for (unsigned int i = 0; i < nterms; i++) {
		if (strncmp (agreedVersion, terms[i].effective, 4+2+2) < 0) {
			agreed = false;
			break;
		}
	}
	if (agreed) {
		pam_syslog (pamh, LOG_DEBUG, "user has agreed to '%s'", agreedVersion);
		ret = PAM_SUCCESS;
		goto finalize;
	}

	agreed = false;
	if ((ret = askUserForAgreement (pamh, &agreed)) != PAM_SUCCESS) {
		goto finalize;
	}
	/* get latest version */
	agreedVersion = generalizedTimeZero;
	for (unsigned int i = 0; i < nterms; i++) {
		if (strncmp (terms[i].effective, agreedVersion, 4+2+2) > 0) {
			agreedVersion = terms[i].effective;
		}
	}
	if (agreed) {
		pam_syslog (pamh, LOG_DEBUG, "setting agreed version to %s", agreedVersion);
		ret = setUserAgreed (&config, pamh, ldap, user, (char *) agreedVersion);
		goto finalize;
	} else {
		ret = PAM_PERM_DENIED;
		goto finalize;
	}

finalize:
	if (ldap != NULL) {
		ldapClose (ldap);
	}
	if (terms != NULL) {
		for (unsigned int i = 0; i < nterms; i++) {
			termsFree (&terms[i]);
		}
		free (terms);
	}
	configFree (&config);

	return ret;
}


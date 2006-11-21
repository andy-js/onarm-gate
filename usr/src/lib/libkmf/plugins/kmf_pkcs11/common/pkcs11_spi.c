/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * PKCS11 token KMF Plugin
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h> /* debugging only */
#include <errno.h>
#include <values.h>

#include <kmfapiP.h>
#include <oidsalg.h>
#include <ber_der.h>
#include <algorithm.h>

#include <cryptoutil.h>
#include <security/cryptoki.h>
#include <security/pkcs11.h>

#define	SETATTR(t, n, atype, value, size) \
	t[n].type = atype; \
	t[n].pValue = (CK_BYTE *)value; \
	t[n].ulValueLen = (CK_ULONG)size;

#define	SET_ERROR(h, c) h->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN; \
	h->lasterr.errcode = c;

typedef struct _objlist {
	CK_OBJECT_HANDLE handle;
	struct _objlist *next;
} OBJLIST;

static KMF_RETURN
search_certs(KMF_HANDLE_T, char *, char *, char *, KMF_BIGINT *,
	boolean_t, KMF_CERT_VALIDITY, OBJLIST **, uint32_t *);

static KMF_RETURN
keyObj2RawKey(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_RAW_KEY_DATA **);

KMF_RETURN
KMFPK11_ConfigureKeystore(KMF_HANDLE_T, KMF_CONFIG_PARAMS *);

KMF_RETURN
KMFPK11_FindCert(KMF_HANDLE_T,
	KMF_FINDCERT_PARAMS *,
	KMF_X509_DER_CERT *,
	uint32_t *);

void
KMFPK11_FreeKMFCert(KMF_HANDLE_T,
	KMF_X509_DER_CERT *kmf_cert);

KMF_RETURN
KMFPK11_StoreCert(KMF_HANDLE_T, KMF_STORECERT_PARAMS *, KMF_DATA *);

KMF_RETURN
KMFPK11_ImportCert(KMF_HANDLE_T, KMF_IMPORTCERT_PARAMS *);

KMF_RETURN
KMFPK11_DeleteCert(KMF_HANDLE_T, KMF_DELETECERT_PARAMS *);

KMF_RETURN
KMFPK11_CreateKeypair(KMF_HANDLE_T, KMF_CREATEKEYPAIR_PARAMS *,
	KMF_KEY_HANDLE *, KMF_KEY_HANDLE *);

KMF_RETURN
KMFPK11_DeleteKey(KMF_HANDLE_T, KMF_DELETEKEY_PARAMS *,
	KMF_KEY_HANDLE *, boolean_t);

KMF_RETURN
KMFPK11_EncodePubKeyData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_DATA *);

KMF_RETURN
KMFPK11_SignData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
KMFPK11_GetErrorString(KMF_HANDLE_T, char **);

KMF_RETURN
KMFPK11_GetPrikeyByCert(KMF_HANDLE_T, KMF_CRYPTOWITHCERT_PARAMS *, KMF_DATA *,
	KMF_KEY_HANDLE *, KMF_KEY_ALG);

KMF_RETURN
KMFPK11_DecryptData(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_OID *,
	KMF_DATA *, KMF_DATA *);

KMF_RETURN
KMFPK11_FindKey(KMF_HANDLE_T, KMF_FINDKEY_PARAMS *,
	KMF_KEY_HANDLE *, uint32_t *);

KMF_RETURN
KMFPK11_StorePrivateKey(KMF_HANDLE_T, KMF_STOREKEY_PARAMS *,
	KMF_RAW_KEY_DATA *);

KMF_RETURN
KMFPK11_CreateSymKey(KMF_HANDLE_T, KMF_CREATESYMKEY_PARAMS *,
	KMF_KEY_HANDLE *);

KMF_RETURN
KMFPK11_GetSymKeyValue(KMF_HANDLE_T, KMF_KEY_HANDLE *, KMF_RAW_SYM_KEY *);

KMF_RETURN
KMFPK11_SetTokenPin(KMF_HANDLE_T, KMF_SETPIN_PARAMS *, KMF_CREDENTIAL *);

static
KMF_PLUGIN_FUNCLIST pk11token_plugin_table =
{
	1,			/* Version */
	KMFPK11_ConfigureKeystore,
	KMFPK11_FindCert,
	KMFPK11_FreeKMFCert,
	KMFPK11_StoreCert,
	KMFPK11_ImportCert,
	NULL,			/* ImportCRL */
	KMFPK11_DeleteCert,
	NULL,			/* DeleteCRL */
	KMFPK11_CreateKeypair,
	KMFPK11_FindKey,
	KMFPK11_EncodePubKeyData,
	KMFPK11_SignData,
	KMFPK11_DeleteKey,
	NULL,			/* ListCRL */
	NULL,			/* FindCRL */
	NULL,			/* FindCertInCRL */
	KMFPK11_GetErrorString,
	KMFPK11_GetPrikeyByCert,
	KMFPK11_DecryptData,
	NULL,			/* ExportP12 */
	KMFPK11_StorePrivateKey,
	KMFPK11_CreateSymKey,
	KMFPK11_GetSymKeyValue,
	KMFPK11_SetTokenPin,
	NULL			/* Finalize */
};

KMF_PLUGIN_FUNCLIST *
KMF_Plugin_Initialize()
{
	return (&pk11token_plugin_table);
}

KMF_RETURN
KMFPK11_ConfigureKeystore(KMF_HANDLE_T handle, KMF_CONFIG_PARAMS *params)
{
	KMF_RETURN rv = KMF_OK;

	if (params == NULL || params->pkcs11config.label == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = KMF_SelectToken(handle, params->pkcs11config.label,
	    params->pkcs11config.readonly);

	return (rv);
}

static KMF_RETURN
pk11_authenticate(KMF_HANDLE_T handle,
	KMF_CREDENTIAL *cred)
{

	CK_RV ck_rv = CKR_OK;
	CK_SESSION_HANDLE hSession = (CK_SESSION_HANDLE)handle->pk11handle;

	if (hSession == NULL)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (cred == NULL || cred->cred == NULL || cred->credlen == 0) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	if ((ck_rv = C_Login(hSession, CKU_USER,
		(uchar_t *)cred->cred, cred->credlen)) != CKR_OK) {
		if (ck_rv != CKR_USER_ALREADY_LOGGED_IN) {
			handle->lasterr.kstype = KMF_KEYSTORE_PK11TOKEN;
			handle->lasterr.errcode = ck_rv;
			return (KMF_ERR_AUTH_FAILED);
		}
	}

	return (KMF_OK);
}

static KMF_RETURN
PK11Cert2KMFCert(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE hObj,
		KMF_X509_DER_CERT *kmfcert)
{
	KMF_RETURN rv = 0;
	CK_RV ckrv = CKR_OK;

	CK_CERTIFICATE_TYPE cktype;
	CK_OBJECT_CLASS	class;
	CK_BBOOL	cktrusted, token;
	CK_ULONG subject_len, value_len, issuer_len, serno_len, id_len;
	CK_BYTE *subject = NULL, *value = NULL;
	CK_BYTE *label = NULL;
	CK_ULONG label_len = 0;
	CK_ATTRIBUTE templ[10];

	SETATTR(templ, 0, CKA_CLASS, &class, sizeof (class));

	/*  Is this a certificate object ? */
	ckrv = C_GetAttributeValue(kmfh->pk11handle, hObj, templ, 1);
	if (ckrv != CKR_OK || class != CKO_CERTIFICATE)  {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	SETATTR(templ, 0, CKA_CERTIFICATE_TYPE, &cktype, sizeof (cktype));
	SETATTR(templ, 1, CKA_TOKEN, &token, sizeof (token));
	SETATTR(templ, 2, CKA_TRUSTED, &cktrusted, sizeof (cktrusted));

	ckrv = C_GetAttributeValue(kmfh->pk11handle, hObj, templ, 3);

	if (ckrv != CKR_OK || cktype != CKC_X_509)  {
		SET_ERROR(kmfh, ckrv);
		return (ckrv);
	} else {
		/* What attributes are available and how big are they? */
		subject_len = issuer_len = serno_len = id_len = value_len =
			label_len = 0;
		SETATTR(templ, 0, CKA_SUBJECT,	NULL, subject_len);
		SETATTR(templ, 1, CKA_ISSUER,	NULL, issuer_len);
		SETATTR(templ, 2, CKA_SERIAL_NUMBER, NULL, serno_len);
		SETATTR(templ, 3, CKA_ID, NULL, id_len);
		SETATTR(templ, 4, CKA_VALUE, NULL, value_len);
		SETATTR(templ, 5, CKA_LABEL, NULL, label_len);

		/*
		 * Query the object with NULL values in the pValue spot
		 * so we know how much space to allocate for each field.
		 */
		ckrv = C_GetAttributeValue(kmfh->pk11handle, hObj, templ, 6);
		if (ckrv != CKR_OK)  {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL); /* TODO - Error messages ? */
		}

		subject_len	= templ[0].ulValueLen;
		issuer_len	= templ[1].ulValueLen;
		serno_len	= templ[2].ulValueLen;
		id_len		= templ[3].ulValueLen;
		value_len	= templ[4].ulValueLen;
		label_len	= templ[5].ulValueLen;

		/*
		 * For PKCS#11 CKC_X_509 certificate objects,
		 * the following attributes must be defined.
		 * CKA_SUBJECT, CKA_ID, CKA_ISSUER, CKA_SERIAL_NUMBER,
		 * CKA_VALUE.
		 */
		if (subject_len == 0 || issuer_len == 0 ||
		    serno_len == 0 || value_len == 0) {
			return (KMF_ERR_INTERNAL);
		}

		/* Only fetch the value field if we are saving the data */
		if (kmfcert != NULL) {
			int i = 0;
			value = malloc(value_len);
			if (value == NULL) {
				rv = KMF_ERR_MEMORY;
				goto errout;
			}

			SETATTR(templ, i, CKA_VALUE, value, value_len);
			i++;
			if (label_len > 0) {
				label = malloc(label_len + 1);
				if (label == NULL) {
					rv = KMF_ERR_MEMORY;
					goto errout;
				}
				(void) memset(label, 0, label_len + 1);
				SETATTR(templ, i, CKA_LABEL, label,
					label_len);
				i++;
			}

			/* re-query the object with room for the value attr */
			ckrv = C_GetAttributeValue(kmfh->pk11handle, hObj,
				templ, i);

			if (ckrv != CKR_OK)  {
				SET_ERROR(kmfh, ckrv);
				rv = KMF_ERR_INTERNAL;
				goto errout;
			}

			kmfcert->certificate.Data = value;
			kmfcert->certificate.Length = value_len;
			kmfcert->kmf_private.flags |= KMF_FLAG_CERT_SIGNED;
			kmfcert->kmf_private.keystore_type =
				KMF_KEYSTORE_PK11TOKEN;
			kmfcert->kmf_private.label = (char *)label;

			rv = KMF_OK;
		}
	}

errout:
	if (rv != KMF_OK) {
		if (subject)
			free(subject);
		if (value)
			free(value);

		if (kmfcert) {
			kmfcert->certificate.Data = NULL;
			kmfcert->certificate.Length = 0;
		}
	}
	return (rv);
}

static void
free_objlist(OBJLIST *head)
{
	OBJLIST *temp = head;

	while (temp != NULL) {
		head = head->next;
		free(temp);
		temp = head;
	}
}

/*
 * The caller should make sure that the templ->pValue is NULL since
 * it will be overwritten below.
 */
static KMF_RETURN
get_attr(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj,
	CK_ATTRIBUTE *templ)
{
	CK_RV rv;

	rv = C_GetAttributeValue(kmfh->pk11handle, obj, templ, 1);
	if (rv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		return (KMF_ERR_INTERNAL);
	}

	if (templ->ulValueLen > 0) {
		templ->pValue = malloc(templ->ulValueLen);
		if (templ->pValue == NULL)
			return (KMF_ERR_MEMORY);

		rv = C_GetAttributeValue(kmfh->pk11handle, obj, templ, 1);
		if (rv != CKR_OK) {
			SET_ERROR(kmfh, rv);
			return (KMF_ERR_INTERNAL);
		}
	}

	return (KMF_OK);
}

/*
 * Match a certificate with an issuer and/or subject name.
 * This is tricky because we cannot reliably compare DER encodings
 * because RDNs may have their AV-pairs in different orders even
 * if the values are the same.  You must compare individual
 * AV pairs for the RDNs.
 *
 * RETURN: 0 for a match, non-zero for a non-match.
 */
static KMF_RETURN
matchcert(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj,
	KMF_X509_NAME *issuer, KMF_X509_NAME *subject)
{
	KMF_RETURN rv = KMF_OK;
	CK_ATTRIBUTE certattr;
	KMF_DATA name;
	KMF_X509_NAME dn;

	if (issuer->numberOfRDNs > 0) {
		certattr.type = CKA_ISSUER;
		certattr.pValue = NULL;
		certattr.ulValueLen = 0;

		rv = get_attr(kmfh, obj, &certattr);

		if (rv == KMF_OK) {
			name.Data = certattr.pValue;
			name.Length = certattr.ulValueLen;
			rv = DerDecodeName(&name, &dn);
			if (rv == KMF_OK) {
				rv = KMF_CompareRDNs(issuer, &dn);
				KMF_FreeDN(&dn);
			}
			free(certattr.pValue);
		}

		if (rv != KMF_OK)
			return (rv);
	}
	if (subject->numberOfRDNs > 0) {
		certattr.type = CKA_SUBJECT;
		certattr.pValue = NULL;
		certattr.ulValueLen = 0;

		rv = get_attr(kmfh, obj, &certattr);

		if (rv == KMF_OK) {
			name.Data = certattr.pValue;
			name.Length = certattr.ulValueLen;
			rv = DerDecodeName(&name, &dn);
			if (rv == KMF_OK) {
				rv = KMF_CompareRDNs(subject, &dn);
				KMF_FreeDN(&dn);
			}
			free(certattr.pValue);
		}
	}

	return (rv);
}

/*
 * delete "curr" node from the "newlist".
 */
static void
pk11_delete_obj_from_list(OBJLIST **newlist,
	OBJLIST **prev, OBJLIST **curr)
{

	if (*curr == *newlist) {
		/* first node in the list */
		*newlist = (*curr)->next;
		*prev = (*curr)->next;
		free(*curr);
		*curr = *newlist;
	} else {
		(*prev)->next = (*curr)->next;
		free(*curr);
		*curr = (*prev)->next;
	}
}

/*
 * prepare_object_search
 *
 * Because this code is shared by the FindCert and
 * DeleteCert functions, put it in a separate routine
 * to save some work and make code easier to debug and
 * read.
 */
static KMF_RETURN
search_certs(KMF_HANDLE_T handle,
	char *label, char *issuer, char *subject, KMF_BIGINT *serial,
	boolean_t private, KMF_CERT_VALIDITY validity,
	OBJLIST **objlist, uint32_t *numobj)
{
	KMF_RETURN rv = KMF_OK;
	CK_RV ckrv = CKR_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CK_ATTRIBUTE templ[10];
	CK_BBOOL true = TRUE;
	CK_OBJECT_CLASS	oclass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE ctype = CKC_X_509;
	KMF_X509_NAME subjectDN, issuerDN;
	int i;
	OBJLIST *newlist, *tail;
	CK_ULONG num = 0;
	uint32_t num_ok_certs = 0; /* number of non-expired or expired certs */

	(void) memset(&templ, 0, 10 * sizeof (CK_ATTRIBUTE));
	(void) memset(&issuerDN, 0, sizeof (KMF_X509_NAME));
	(void) memset(&subjectDN, 0, sizeof (KMF_X509_NAME));
	i = 0;
	SETATTR(templ, i, CKA_TOKEN, &true, sizeof (true)); i++;
	SETATTR(templ, i, CKA_CLASS, &oclass, sizeof (oclass)); i++;
	SETATTR(templ, i, CKA_CERTIFICATE_TYPE, &ctype,
		sizeof (ctype)); i++;

	if (label != NULL && strlen(label)) {
		SETATTR(templ, i, CKA_LABEL, label, strlen(label));
		i++;
	}
	if (private) {
		SETATTR(templ, i, CKA_PRIVATE, &true, sizeof (true)); i++;
	}

	if (issuer != NULL && strlen(issuer)) {
		if ((rv = KMF_DNParser(issuer, &issuerDN)) != KMF_OK)
			return (rv);
	}
	if (subject != NULL && strlen(subject)) {
		if ((rv = KMF_DNParser(subject, &subjectDN)) != KMF_OK)
			return (rv);
	}

	if (serial != NULL && serial->val != NULL && serial->len > 0) {
		SETATTR(templ, i, CKA_SERIAL_NUMBER,
			serial->val, serial->len);
		i++;
	}

	(*numobj) = 0;
	*objlist = NULL;
	newlist = NULL;

	ckrv = C_FindObjectsInit(kmfh->pk11handle, templ, i);
	if (ckrv != CKR_OK)
		goto cleanup;

	tail = newlist = NULL;
	while (ckrv == CKR_OK) {
		CK_OBJECT_HANDLE tObj;
		ckrv = C_FindObjects(kmfh->pk11handle, &tObj, 1, &num);
		if (ckrv != CKR_OK || num == 0)
			break;

		/*
		 * 'matchcert' returns 0 if subject/issuer match
		 *
		 * If no match, move on to the next one
		 */
		if (matchcert(kmfh, tObj, &issuerDN, &subjectDN))
			continue;

		if (newlist == NULL) {
			newlist = malloc(sizeof (OBJLIST));
			if (newlist == NULL) {
				rv = KMF_ERR_MEMORY;
				break;
			}
			newlist->handle = tObj;
			newlist->next = NULL;
			tail = newlist;
		} else {
			tail->next = malloc(sizeof (OBJLIST));
			if (tail->next != NULL) {
				tail = tail->next;
			} else {
				rv = KMF_ERR_MEMORY;
				break;
			}
			tail->handle = tObj;
			tail->next = NULL;
		}
		(*numobj)++;
	}
	ckrv = C_FindObjectsFinal(kmfh->pk11handle);

cleanup:
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		if (newlist != NULL) {
			free_objlist(newlist);
			*numobj = 0;
			newlist = NULL;
		}
	} else {
		if (validity == KMF_ALL_CERTS) {
			*objlist = newlist;
		} else {
			OBJLIST *node, *prev;
			KMF_X509_DER_CERT  tmp_kmf_cert;
			uint32_t i = 0;

			node = prev = newlist;
			/*
			 * Now check to see if any found certificate is expired
			 * or valid.
			 */
			while (node != NULL && i < (*numobj)) {
				(void) memset(&tmp_kmf_cert, 0,
				    sizeof (KMF_X509_DER_CERT));
				rv = PK11Cert2KMFCert(kmfh, node->handle,
				    &tmp_kmf_cert);
				if (rv != KMF_OK) {
					goto cleanup1;
				}

				rv = KMF_CheckCertDate(handle,
				    &tmp_kmf_cert.certificate);

				if (validity == KMF_NONEXPIRED_CERTS) {
					if (rv == KMF_OK)  {
						num_ok_certs++;
						prev = node;
						node = node->next;
					} else if (rv ==
					    KMF_ERR_VALIDITY_PERIOD) {
						/*
						 * expired - remove it from list
						 */
						pk11_delete_obj_from_list(
						    &newlist, &prev, &node);
					} else {
						goto cleanup1;
					}
				}

				if (validity == KMF_EXPIRED_CERTS) {
					if (rv == KMF_ERR_VALIDITY_PERIOD)  {
						num_ok_certs++;
						prev = node;
						node = node->next;
						rv = KMF_OK;
					} else if (rv == KMF_OK) {
						/*
						 * valid - remove it from list
						 */
						pk11_delete_obj_from_list(
						    &newlist, &prev, &node);
					} else {
						goto cleanup1;
					}
				}
				i++;
				KMF_FreeKMFCert(handle, &tmp_kmf_cert);
			}
			*numobj = num_ok_certs;
			*objlist = newlist;
		}
	}

cleanup1:
	if (rv != KMF_OK && newlist != NULL) {
		free_objlist(newlist);
		*numobj = 0;
		*objlist = NULL;
	}

	if (issuer != NULL)
		KMF_FreeDN(&issuerDN);

	if (subject != NULL)
		KMF_FreeDN(&subjectDN);

	return (rv);
}

/*
 * The caller may pass a NULL value for kmf_cert below and the function will
 * just return the number of certs found (in num_certs).
 */
KMF_RETURN
KMFPK11_FindCert(KMF_HANDLE_T handle, KMF_FINDCERT_PARAMS *params,
	KMF_X509_DER_CERT *kmf_cert,
	uint32_t *num_certs)
{
	KMF_RETURN rv = 0;
	uint32_t want_certs;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	OBJLIST *objlist = NULL;

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (params == NULL || num_certs == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (*num_certs > 0)
		want_certs = *num_certs;
	else
		want_certs = MAXINT; /* count them all */

	*num_certs = 0;

	rv = search_certs(handle,
		params->certLabel, params->issuer,
		params->subject, params->serial,
		params->pkcs11parms.private,
		params->find_cert_validity,
		&objlist, num_certs);

	if (rv == KMF_OK && objlist != NULL && kmf_cert != NULL) {
		OBJLIST *node = objlist;
		int i = 0;
		while (node != NULL && i < want_certs) {
			rv = PK11Cert2KMFCert(kmfh, node->handle,
				&kmf_cert[i]);
			i++;
			node = node->next;
		}
	}

	if (objlist != NULL)
		free_objlist(objlist);

	if (*num_certs == 0)
		rv = KMF_ERR_CERT_NOT_FOUND;

	return (rv);
}

/*ARGSUSED*/
void
KMFPK11_FreeKMFCert(KMF_HANDLE_T handle,
	KMF_X509_DER_CERT *kmf_cert)
{
	if (kmf_cert != NULL && kmf_cert->certificate.Data != NULL) {
		free(kmf_cert->certificate.Data);
		kmf_cert->certificate.Data = NULL;
		kmf_cert->certificate.Length = 0;

		if (kmf_cert->kmf_private.label != NULL) {
			free(kmf_cert->kmf_private.label);
			kmf_cert->kmf_private.label = NULL;
		}
	}
}

KMF_RETURN
KMFPK11_EncodePubKeyData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *pKey,
		KMF_DATA *eData)
{
	KMF_RETURN ret = KMF_OK;
	CK_RV rv;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CK_OBJECT_CLASS ckObjClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE ckKeyType;
	KMF_DATA Modulus, Exponent, Prime, Subprime, Base, Value;
	KMF_OID *Algorithm;
	BerElement *asn1 = NULL;
	BerValue *PubKeyParams = NULL, *EncodedKey = NULL;
	KMF_X509_SPKI spki;

	CK_ATTRIBUTE rsaTemplate[4];
	CK_ATTRIBUTE dsaTemplate[6];

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (pKey == NULL || pKey->keyp == CK_INVALID_HANDLE)
		return (KMF_ERR_BAD_PARAMETER);

	(void) memset(&Modulus, 0, sizeof (Modulus));
	(void) memset(&Exponent, 0, sizeof (Exponent));
	(void) memset(&Prime, 0, sizeof (Prime));
	(void) memset(&Subprime, 0, sizeof (Subprime));
	(void) memset(&Base, 0, sizeof (Base));
	(void) memset(&Value, 0, sizeof (Value));

	SETATTR(rsaTemplate, 0, CKA_CLASS, &ckObjClass, sizeof (ckObjClass));
	SETATTR(rsaTemplate, 1, CKA_KEY_TYPE, &ckKeyType, sizeof (ckKeyType));
	SETATTR(rsaTemplate, 2, CKA_MODULUS, Modulus.Data, &Modulus.Length);
	SETATTR(rsaTemplate, 3, CKA_PUBLIC_EXPONENT, Exponent.Data,
		&Exponent.Length);

	SETATTR(dsaTemplate, 0, CKA_CLASS, &ckObjClass, sizeof (ckObjClass));
	SETATTR(dsaTemplate, 1, CKA_KEY_TYPE, &ckKeyType, sizeof (ckKeyType));
	SETATTR(dsaTemplate, 2, CKA_PRIME, Prime.Data, &Prime.Length);
	SETATTR(dsaTemplate, 3, CKA_SUBPRIME, Subprime.Data, &Subprime.Length);
	SETATTR(dsaTemplate, 4, CKA_BASE, Base.Data, &Base.Length);
	SETATTR(dsaTemplate, 5, CKA_VALUE, Value.Data, &Value.Length);

	switch (pKey->keyalg) {
		case KMF_RSA:
			/* Get the length of the fields */
			rv = C_GetAttributeValue(kmfh->pk11handle,
				(CK_OBJECT_HANDLE)pKey->keyp,
				rsaTemplate, 4);
			if (rv != CKR_OK) {
				SET_ERROR(kmfh, rv);
				return (KMF_ERR_BAD_PARAMETER);
			}

			Modulus.Length = rsaTemplate[2].ulValueLen;
			Modulus.Data = malloc(Modulus.Length);
			if (Modulus.Data == NULL)
				return (KMF_ERR_MEMORY);

			Exponent.Length = rsaTemplate[3].ulValueLen;
			Exponent.Data = malloc(Exponent.Length);
			if (Exponent.Data == NULL) {
				free(Modulus.Data);
				return (KMF_ERR_MEMORY);
			}

			SETATTR(rsaTemplate, 2, CKA_MODULUS, Modulus.Data,
					Modulus.Length);
			SETATTR(rsaTemplate, 3, CKA_PUBLIC_EXPONENT,
					Exponent.Data, Exponent.Length);
			/* Now get the values */
			rv = C_GetAttributeValue(kmfh->pk11handle,
				(CK_OBJECT_HANDLE)pKey->keyp,
				rsaTemplate, 4);
			if (rv != CKR_OK) {
				SET_ERROR(kmfh, rv);
				free(Modulus.Data);
				free(Exponent.Data);
				return (KMF_ERR_BAD_PARAMETER);
			}

			/*
			 * This is the KEY algorithm, not the
			 * signature algorithm.
			 */
			Algorithm = X509_AlgIdToAlgorithmOid(KMF_ALGID_RSA);
			if (Algorithm != NULL) {

				/* Encode the RSA Key Data */
				if ((asn1 = kmfder_alloc()) == NULL) {
					free(Modulus.Data);
					free(Exponent.Data);
					return (KMF_ERR_MEMORY);
				}
				if (kmfber_printf(asn1, "{II}",
					Modulus.Data, Modulus.Length,
					Exponent.Data, Exponent.Length) == -1) {
					kmfber_free(asn1, 1);
					free(Modulus.Data);
					free(Exponent.Data);
					return (KMF_ERR_ENCODING);
				}
				if (kmfber_flatten(asn1, &EncodedKey) == -1) {
					kmfber_free(asn1, 1);
					free(Modulus.Data);
					free(Exponent.Data);
					return (KMF_ERR_ENCODING);
				}
				kmfber_free(asn1, 1);
			}

			free(Exponent.Data);
			free(Modulus.Data);

			break;
		case KMF_DSA:
			/* Get the length of the fields */
			rv = C_GetAttributeValue(kmfh->pk11handle,
				(CK_OBJECT_HANDLE)pKey->keyp,
				dsaTemplate, 6);
			if (rv != CKR_OK) {
				SET_ERROR(kmfh, rv);
				return (KMF_ERR_BAD_PARAMETER);
			}
			Prime.Length = dsaTemplate[2].ulValueLen;
			Prime.Data = malloc(Prime.Length);
			if (Prime.Data == NULL) {
				return (KMF_ERR_MEMORY);
			}

			Subprime.Length = dsaTemplate[3].ulValueLen;
			Subprime.Data = malloc(Subprime.Length);
			if (Subprime.Data == NULL) {
				free(Prime.Data);
				return (KMF_ERR_MEMORY);
			}

			Base.Length = dsaTemplate[4].ulValueLen;
			Base.Data = malloc(Base.Length);
			if (Base.Data == NULL) {
				free(Prime.Data);
				free(Subprime.Data);
				return (KMF_ERR_MEMORY);
			}

			Value.Length = dsaTemplate[5].ulValueLen;
			Value.Data = malloc(Value.Length);
			if (Value.Data == NULL) {
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				return (KMF_ERR_MEMORY);
			}
			SETATTR(dsaTemplate, 2, CKA_PRIME, Prime.Data,
					Prime.Length);
			SETATTR(dsaTemplate, 3, CKA_SUBPRIME, Subprime.Data,
					Subprime.Length);
			SETATTR(dsaTemplate, 4, CKA_BASE, Base.Data,
					Base.Length);
			SETATTR(dsaTemplate, 5, CKA_VALUE, Value.Data,
					Value.Length);

			/* Now get the values */
			rv = C_GetAttributeValue(kmfh->pk11handle,
				(CK_OBJECT_HANDLE)pKey->keyp,
				dsaTemplate, 6);
			if (rv != CKR_OK) {
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				free(Value.Data);
				SET_ERROR(kmfh, rv);
				return (KMF_ERR_BAD_PARAMETER);
			}
			/*
			 * This is the KEY algorithm, not the
			 * signature algorithm.
			 */
			Algorithm =
			    X509_AlgIdToAlgorithmOid(KMF_ALGID_DSA);

			/* Encode the DSA Algorithm Parameters */
			if ((asn1 = kmfder_alloc()) == NULL) {
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				free(Value.Data);
				return (KMF_ERR_MEMORY);
			}

			if (kmfber_printf(asn1, "{III}",
				Prime.Data, Prime.Length,
				Subprime.Data, Subprime.Length,
				Base.Data, Base.Length) == -1) {

				kmfber_free(asn1, 1);
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				free(Value.Data);
				return (KMF_ERR_ENCODING);
			}
			if (kmfber_flatten(asn1, &PubKeyParams) == -1) {
				kmfber_free(asn1, 1);
				free(Prime.Data);
				free(Subprime.Data);
				free(Base.Data);
				free(Value.Data);
				return (KMF_ERR_ENCODING);
			}
			kmfber_free(asn1, 1);
			free(Prime.Data);
			free(Subprime.Data);
			free(Base.Data);

			/* Encode the DSA Key Value */
			if ((asn1 = kmfder_alloc()) == NULL) {
				free(Value.Data);
				return (KMF_ERR_MEMORY);
			}

			if (kmfber_printf(asn1, "I",
				Value.Data, Value.Length) == -1) {
				kmfber_free(asn1, 1);
				free(Value.Data);
				return (KMF_ERR_ENCODING);
			}
			if (kmfber_flatten(asn1, &EncodedKey) == -1) {
				kmfber_free(asn1, 1);
				free(Value.Data);
				return (KMF_ERR_ENCODING);
			}
			kmfber_free(asn1, 1);
			free(Value.Data);
			break;
		default:
			return (KMF_ERR_BAD_PARAMETER);
	}

	/* Now, build an SPKI structure for the final encoding step */
	spki.algorithm.algorithm = *Algorithm;
	if (PubKeyParams != NULL) {
		spki.algorithm.parameters.Data =
			(uchar_t *)PubKeyParams->bv_val;
		spki.algorithm.parameters.Length = PubKeyParams->bv_len;
	} else {
		spki.algorithm.parameters.Data = NULL;
		spki.algorithm.parameters.Length = 0;
	}

	if (EncodedKey != NULL) {
		spki.subjectPublicKey.Data = (uchar_t *)EncodedKey->bv_val;
		spki.subjectPublicKey.Length = EncodedKey->bv_len;
	} else {
		spki.subjectPublicKey.Data = NULL;
		spki.subjectPublicKey.Length = 0;
	}

	/* Finally, encode the entire SPKI record */
	ret = DerEncodeSPKI(&spki, eData);

cleanup:
	if (EncodedKey) {
		free(EncodedKey->bv_val);
		free(EncodedKey);
	}

	if (PubKeyParams) {
		free(PubKeyParams->bv_val);
		free(PubKeyParams);
	}

	return (ret);
}


static KMF_RETURN
CreateCertObject(KMF_HANDLE_T handle, char *label, KMF_DATA *pcert)
{
	KMF_RETURN rv = 0;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	KMF_X509_CERTIFICATE *signed_cert_ptr = NULL;
	KMF_DATA data;
	KMF_DATA Id;

	CK_RV ckrv;
	CK_ULONG subject_len, issuer_len, serno_len;
	CK_BYTE *subject, *issuer, *serial;
	CK_BBOOL true = TRUE;
	CK_CERTIFICATE_TYPE certtype = CKC_X_509;
	CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	CK_ATTRIBUTE x509templ[11];
	CK_OBJECT_HANDLE hCert = NULL;
	int i;

	if (!kmfh)
		return (KMF_ERR_INTERNAL); /* should not happen */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_INTERNAL); /* should not happen */

	if (pcert == NULL || pcert->Data == NULL || pcert->Length == 0)
		return (KMF_ERR_INTERNAL);  /* should not happen */

	/*
	 * The data *must* be a DER encoded X.509 certificate.
	 * Convert it to a CSSM cert and then parse the fields so
	 * the PKCS#11 attributes can be filled in correctly.
	 */
	rv = DerDecodeSignedCertificate((const KMF_DATA *)pcert,
		&signed_cert_ptr);
	if (rv != KMF_OK) {
		return (KMF_ERR_ENCODING);
	}

	/*
	 * Encode fields into PKCS#11 attributes.
	 */

	/* Get the subject name */
	rv = DerEncodeName(&signed_cert_ptr->certificate.subject, &data);
	if (rv == KMF_OK) {
		subject = data.Data;
		subject_len = data.Length;
	} else {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}

	/* Encode the issuer */
	rv = DerEncodeName(&signed_cert_ptr->certificate.issuer, &data);
	if (rv == KMF_OK) {
		issuer = data.Data;
		issuer_len = data.Length;
	} else {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}

	/* Encode serial number */
	if (signed_cert_ptr->certificate.serialNumber.len > 0 &&
	    signed_cert_ptr->certificate.serialNumber.val != NULL) {
		serial = signed_cert_ptr->certificate.serialNumber.val;
		serno_len = signed_cert_ptr->certificate.serialNumber.len;
	} else {
		rv = KMF_ERR_ENCODING;
		goto cleanup;
	}

	/* Generate an ID from the SPKI data */
	rv = GetIDFromSPKI(&signed_cert_ptr->certificate.subjectPublicKeyInfo,
			&Id);

	if (rv != KMF_OK) {
		SET_ERROR(kmfh, rv);
		goto cleanup;
	}

	i = 0;
	SETATTR(x509templ, i, CKA_CLASS, &certClass,
		sizeof (certClass)); i++;
	SETATTR(x509templ, i, CKA_CERTIFICATE_TYPE, &certtype,
		sizeof (certtype)); i++;
	SETATTR(x509templ, i, CKA_TOKEN, &true, sizeof (true)); i++;
	SETATTR(x509templ, i, CKA_SUBJECT, subject, subject_len); i++;
	SETATTR(x509templ, i, CKA_ISSUER, issuer, issuer_len); i++;
	SETATTR(x509templ, i, CKA_SERIAL_NUMBER, serial, serno_len); i++;
	SETATTR(x509templ, i, CKA_VALUE, pcert->Data, pcert->Length); i++;
	SETATTR(x509templ, i, CKA_ID, Id.Data, Id.Length); i++;
	if (label != NULL && strlen(label)) {
		SETATTR(x509templ, i, CKA_LABEL, label, strlen(label));
		i++;
	}

	/*
	 * The cert object handle is actually "leaked" here.  If the app
	 * really wants to clean up the data space, it will have to call
	 * KMF_DeleteCert and specify the softtoken keystore.
	 */
	ckrv = C_CreateObject(kmfh->pk11handle, x509templ, i, &hCert);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		rv = KMF_ERR_INTERNAL;
	}
	free(subject);
	free(issuer);

cleanup:
	if (Id.Data != NULL)
		free(Id.Data);

	if (signed_cert_ptr) {
		KMF_FreeSignedCert(signed_cert_ptr);
		free(signed_cert_ptr);
	}
	return (rv);
}


KMF_RETURN
KMFPK11_StoreCert(KMF_HANDLE_T handle, KMF_STORECERT_PARAMS *params,
		KMF_DATA *pcert)
{
	KMF_RETURN rv = 0;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (pcert == NULL || pcert->Data == NULL || pcert->Length == 0)
		return (KMF_ERR_BAD_PARAMETER);

	rv = CreateCertObject(handle, params->certLabel, pcert);
	return (rv);
}



KMF_RETURN
KMFPK11_ImportCert(KMF_HANDLE_T handle, KMF_IMPORTCERT_PARAMS *params)
{
	KMF_RETURN rv = 0;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_ENCODE_FORMAT format;
	KMF_DATA  cert1 = { NULL, 0};
	KMF_DATA  cert2 = { NULL, 0};

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (params == NULL || params->certfile == NULL) {
		return (KMF_ERR_BAD_PARAMETER);
	}

	/*
	 * Check if the input cert file is a valid certificate and
	 * auto-detect the file format of it.
	 */
	rv = KMF_IsCertFile(handle, params->certfile, &format);
	if (rv != KMF_OK)
		return (rv);

	/* Read in the CERT file */
	rv = KMF_ReadInputFile(handle, params->certfile, &cert1);
	if (rv != KMF_OK) {
		return (rv);
	}

	/*
	 * If the input certificate is in PEM format, we need to convert
	 * it to DER first.
	 */
	if (format == KMF_FORMAT_PEM) {
		int derlen;
		rv = KMF_Pem2Der(cert1.Data, cert1.Length,
		    &cert2.Data, &derlen);
		if (rv != KMF_OK) {
			goto out;
		}
		cert2.Length = (size_t)derlen;
	}

	rv = CreateCertObject(handle, params->certLabel,
	    format == KMF_FORMAT_ASN1 ? &cert1 : &cert2);

out:
	if (cert1.Data != NULL) {
		free(cert1.Data);
	}

	if (cert2.Data != NULL) {
		free(cert2.Data);
	}

	return (rv);
}

KMF_RETURN
KMFPK11_DeleteCert(KMF_HANDLE_T handle, KMF_DELETECERT_PARAMS *params)
{
	KMF_RETURN rv = 0;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	OBJLIST *objlist;
	uint32_t numObjects = 0;

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (params == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/*
	 * Use the same search routine as is used for the FindCert
	 * operation.
	 */
	objlist = NULL;
	rv = search_certs(handle,
		params->certLabel, params->issuer,
		params->subject, params->serial,
		params->pkcs11parms.private,
		params->find_cert_validity,
		&objlist, &numObjects);

	if (rv == KMF_OK && objlist != NULL) {
		OBJLIST *node = objlist;

		while (node != NULL) {
			CK_RV ckrv;
			ckrv = C_DestroyObject(kmfh->pk11handle,
				node->handle);
			if (ckrv != CKR_OK) {
				SET_ERROR(kmfh, ckrv);
				rv = KMF_ERR_INTERNAL;
				break;
			}
			node = node->next;
		}
		free_objlist(objlist);
	}

	if (rv == KMF_OK && numObjects == 0)
		rv = KMF_ERR_CERT_NOT_FOUND;

out:
	return (rv);
}

KMF_RETURN
KMFPK11_CreateKeypair(KMF_HANDLE_T handle, KMF_CREATEKEYPAIR_PARAMS *params,
	KMF_KEY_HANDLE *privkey, KMF_KEY_HANDLE *pubkey)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	CK_RV			ckrv = 0;
	CK_OBJECT_HANDLE	pubKey = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE	priKey = CK_INVALID_HANDLE;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;

	static CK_OBJECT_CLASS	priClass = CKO_PRIVATE_KEY;
	static CK_OBJECT_CLASS	pubClass = CKO_PUBLIC_KEY;

	static CK_ULONG	rsaKeyType = CKK_RSA;
	static CK_ULONG	modulusBits = 1024;
	static CK_BYTE	PubExpo[3] = {0x01, 0x00, 0x01};
	static CK_BBOOL	true = TRUE;
	static CK_BBOOL	ontoken = TRUE;
	static CK_BBOOL	false = FALSE;
	static CK_ULONG	dsaKeyType = CKK_DSA;

	CK_ATTRIBUTE rsaPubKeyTemplate[8];
	CK_ATTRIBUTE rsaPriKeyTemplate[6];

	static CK_BYTE ckDsaPrime[128] = {
	0xb2, 0x6b, 0xc3, 0xfb, 0xe3, 0x26, 0xf4, 0xc2,
	0xcf, 0xdd, 0xf9, 0xae, 0x3e, 0x39, 0x7f, 0x9c,
	0xa7, 0x73, 0xc3, 0x00, 0xa3, 0x50, 0x67, 0xc3,
	0xab, 0x49, 0x2c, 0xea, 0x59, 0x10, 0xa4, 0xbc,
	0x09, 0x94, 0xa9, 0x05, 0x3b, 0x0d, 0x35, 0x3c,
	0x55, 0x52, 0x47, 0xf0, 0xe3, 0x72, 0x5b, 0xe8,
	0x72, 0xa0, 0x71, 0x1c, 0x23, 0x4f, 0x6d, 0xe8,
	0xac, 0xe5, 0x21, 0x1b, 0xc0, 0xd8, 0x42, 0xd3,
	0x87, 0xae, 0x83, 0x5e, 0x52, 0x7e, 0x46, 0x09,
	0xb5, 0xc7, 0x3d, 0xd6, 0x00, 0xf5, 0xf2, 0x9c,
	0x84, 0x30, 0x81, 0x7e, 0x7b, 0x30, 0x5b, 0xd5,
	0xab, 0xd0, 0x2f, 0x21, 0xb3, 0xd8, 0xed, 0xdb,
	0x97, 0x77, 0xe4, 0x7e, 0x6c, 0xcc, 0xb9, 0x6b,
	0xdd, 0xaa, 0x96, 0x04, 0xe7, 0xd4, 0x55, 0x11,
	0x53, 0xab, 0xba, 0x95, 0x9a, 0xa2, 0x8c, 0x27,
	0xd9, 0xcf, 0xad, 0xf3, 0xcf, 0x3a, 0x0c, 0x4b};

	static CK_BYTE ckDsaSubPrime[20] = {
	0xa4, 0x5f, 0x2a, 0x27, 0x09, 0x49, 0xb6, 0xfe,
	0x73, 0xeb, 0x95, 0x7d, 0x00, 0xf3, 0x42, 0xfc,
	0x78, 0x47, 0xb0, 0xd5};

	static CK_BYTE ckDsaBase[128] = {
	0x5c, 0x57, 0x16, 0x49, 0xef, 0xc8, 0xfb, 0x4b,
	0xee, 0x07, 0x45, 0x3b, 0x6a, 0x1d, 0xf3, 0xe5,
	0xeb, 0xee, 0xad, 0x11, 0x13, 0xe3, 0x52, 0xe3,
	0x0d, 0xc0, 0x21, 0x25, 0xfa, 0xf0, 0x93, 0x1c,
	0x53, 0x4d, 0xdc, 0x0d, 0x76, 0xd2, 0xfe, 0xc2,
	0xd7, 0x72, 0x64, 0x69, 0x53, 0x3d, 0x33, 0xbd,
	0xe1, 0x34, 0xf2, 0x5a, 0x67, 0x83, 0xe0, 0xd3,
	0x1c, 0xd6, 0x41, 0x4d, 0x16, 0xe8, 0x6c, 0x5a,
	0x07, 0x95, 0x21, 0x9a, 0xa3, 0xc4, 0xb9, 0x05,
	0x9d, 0x11, 0xcb, 0xc8, 0xc4, 0x9d, 0x00, 0x1a,
	0xf4, 0x85, 0x2a, 0xa9, 0x20, 0x3c, 0xba, 0x67,
	0xe5, 0xed, 0x31, 0xb2, 0x11, 0xfb, 0x1f, 0x73,
	0xec, 0x61, 0x29, 0xad, 0xc7, 0x68, 0xb2, 0x3f,
	0x38, 0xea, 0xd9, 0x87, 0x83, 0x9e, 0x7e, 0x19,
	0x18, 0xdd, 0xc2, 0xc3, 0x5b, 0x16, 0x6d, 0xce,
	0xcf, 0x88, 0x91, 0x07, 0xe0, 0x2b, 0xa8, 0x54 };

	static CK_ATTRIBUTE ckDsaPubKeyTemplate[] = {
	{ CKA_CLASS, &pubClass, sizeof (pubClass) },
	{ CKA_KEY_TYPE, &dsaKeyType, sizeof (dsaKeyType) },
	{ CKA_TOKEN, &ontoken, sizeof (ontoken)},
	{ CKA_PRIVATE, &false, sizeof (false)},
	{ CKA_PRIME, &ckDsaPrime, sizeof (ckDsaPrime) },
	{ CKA_SUBPRIME, &ckDsaSubPrime, sizeof (ckDsaSubPrime)},
	{ CKA_BASE, &ckDsaBase, sizeof (ckDsaBase) },
	{ CKA_VERIFY, &true, sizeof (true) },
};

#define	NUMBER_DSA_PUB_TEMPLATES (sizeof (ckDsaPubKeyTemplate) / \
					sizeof (CK_ATTRIBUTE))
#define	MAX_DSA_PUB_TEMPLATES (sizeof (ckDsaPubKeyTemplate) / \
				    sizeof (CK_ATTRIBUTE))

	static CK_ATTRIBUTE ckDsaPriKeyTemplate[] = {
	{CKA_CLASS, &priClass, sizeof (priClass)},
	{CKA_KEY_TYPE, &dsaKeyType, sizeof (dsaKeyType)},
	{CKA_TOKEN, &ontoken, sizeof (ontoken)},
	{CKA_PRIVATE, &true, sizeof (true)},
	{CKA_SIGN, &true, sizeof (true)},
	};

	CK_ATTRIBUTE labelattr[1];
	CK_ATTRIBUTE idattr[1];
	char IDHashData[SHA1_HASH_LENGTH];
	KMF_DATA IDInput, IDOutput;

#define	NUMBER_DSA_PRI_TEMPLATES (sizeof (ckDsaPriKeyTemplate) / \
					sizeof (CK_ATTRIBUTE))
#define	MAX_DSA_PRI_TEMPLATES (sizeof (ckDsaPriKeyTemplate) / \
				sizeof (CK_ATTRIBUTE))

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (params == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = pk11_authenticate(handle, &params->cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	if (params->keytype == KMF_RSA) {
		CK_MECHANISM keyGenMech = {CKM_RSA_PKCS_KEY_PAIR_GEN,
			NULL, 0};
		CK_BYTE *modulus;
		CK_ULONG modulusLength;
		CK_ATTRIBUTE modattr[1];

		SETATTR(rsaPubKeyTemplate, 0, CKA_CLASS,
			&pubClass, sizeof (pubClass));
		SETATTR(rsaPubKeyTemplate, 1, CKA_KEY_TYPE,
			&rsaKeyType, sizeof (rsaKeyType));
		SETATTR(rsaPubKeyTemplate, 2, CKA_TOKEN,
			&false, sizeof (false));
		SETATTR(rsaPubKeyTemplate, 3, CKA_PRIVATE,
			&false, sizeof (false));
		SETATTR(rsaPubKeyTemplate, 4, CKA_MODULUS_BITS,
			&modulusBits, sizeof (modulusBits));
		if (params->rsa_exponent.len > 0 &&
			params->rsa_exponent.val != NULL) {
			SETATTR(rsaPubKeyTemplate, 5,
				CKA_PUBLIC_EXPONENT,
				params->rsa_exponent.val,
				params->rsa_exponent.len);
		} else {
			SETATTR(rsaPubKeyTemplate, 5,
				CKA_PUBLIC_EXPONENT, &PubExpo,
				sizeof (PubExpo));
		}
		SETATTR(rsaPubKeyTemplate, 6, CKA_ENCRYPT,
			&true, sizeof (true));
		SETATTR(rsaPubKeyTemplate, 7, CKA_VERIFY,
			&true, sizeof (true));

		SETATTR(rsaPriKeyTemplate, 0, CKA_CLASS, &priClass,
			sizeof (priClass));
		SETATTR(rsaPriKeyTemplate, 1, CKA_KEY_TYPE, &rsaKeyType,
			sizeof (rsaKeyType));
		SETATTR(rsaPriKeyTemplate, 2, CKA_TOKEN, &ontoken,
			sizeof (ontoken));
		SETATTR(rsaPriKeyTemplate, 3, CKA_PRIVATE, &true,
			sizeof (true));
		SETATTR(rsaPriKeyTemplate, 4, CKA_DECRYPT, &true,
			sizeof (true));
		SETATTR(rsaPriKeyTemplate, 5, CKA_SIGN, &true,
			sizeof (true));

		SETATTR(modattr, 0, CKA_MODULUS, NULL, &modulusLength);

		modulusBits = params->keylength;

		pubKey = CK_INVALID_HANDLE;
		priKey = CK_INVALID_HANDLE;
		ckrv = C_GenerateKeyPair(hSession, &keyGenMech,
			rsaPubKeyTemplate,
			(sizeof (rsaPubKeyTemplate)/sizeof (CK_ATTRIBUTE)),
			rsaPriKeyTemplate,
			(sizeof (rsaPriKeyTemplate)/sizeof (CK_ATTRIBUTE)),
			&pubKey, &priKey);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_KEYGEN_FAILED);
		}

		if (privkey != NULL) {
			privkey->kstype = KMF_KEYSTORE_PK11TOKEN;
			privkey->keyalg = KMF_RSA;
			privkey->keyclass = KMF_ASYM_PRI;
			privkey->keyp = (void *)priKey;
		}
		if (pubkey != NULL) {
			pubkey->kstype = KMF_KEYSTORE_PK11TOKEN;
			pubkey->keyalg = KMF_RSA;
			pubkey->keyclass = KMF_ASYM_PUB;
			pubkey->keyp = (void *)pubKey;
		}

		/* Get the Modulus field to use as input for creating the ID */
		rv = C_GetAttributeValue(kmfh->pk11handle,
			(CK_OBJECT_HANDLE)pubKey,
			modattr, 1);
		if (rv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_BAD_PARAMETER);
		}

		modulusLength = modattr[0].ulValueLen;
		modulus = malloc(modulusLength);
		if (modulus == NULL)
			return (KMF_ERR_MEMORY);

		modattr[0].pValue = modulus;
		rv = C_GetAttributeValue(kmfh->pk11handle,
			(CK_OBJECT_HANDLE)pubKey,
			modattr, 1);
		if (rv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			free(modulus);
			return (KMF_ERR_BAD_PARAMETER);
		}

		IDInput.Data = modulus;
		IDInput.Length = modulusLength;

	} else if (params->keytype == KMF_DSA) {
		CK_MECHANISM keyGenMech = {CKM_DSA_KEY_PAIR_GEN, NULL, 0};
		CK_BYTE *keyvalue;
		CK_ULONG valueLen;
		CK_ATTRIBUTE valattr[1];

		SETATTR(ckDsaPriKeyTemplate, 2, CKA_TOKEN,
				&ontoken, sizeof (ontoken));
		SETATTR(valattr, 0, CKA_VALUE, NULL, &valueLen);

		ckrv = C_GenerateKeyPair(hSession, &keyGenMech,
			ckDsaPubKeyTemplate,
			(sizeof (ckDsaPubKeyTemplate)/sizeof (CK_ATTRIBUTE)),
			ckDsaPriKeyTemplate,
			(sizeof (ckDsaPriKeyTemplate)/sizeof (CK_ATTRIBUTE)),
			&pubKey, &priKey);
		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_KEYGEN_FAILED);
		}

		if (privkey != NULL) {
			privkey->kstype = KMF_KEYSTORE_PK11TOKEN;
			privkey->keyalg = KMF_DSA;
			privkey->keyclass = KMF_ASYM_PRI;
			privkey->keyp = (void *)priKey;
		}
		if (pubkey != NULL) {
			pubkey->kstype = KMF_KEYSTORE_PK11TOKEN;
			pubkey->keyalg = KMF_DSA;
			pubkey->keyclass = KMF_ASYM_PUB;
			pubkey->keyp = (void *)pubKey;
		}
		/* Get the Public Value to use as input for creating the ID */
		rv = C_GetAttributeValue(hSession,
			(CK_OBJECT_HANDLE)pubKey,
			valattr, 1);
		if (rv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_BAD_PARAMETER);
		}

		valueLen = valattr[0].ulValueLen;
		keyvalue = malloc(valueLen);
		if (keyvalue == NULL)
			return (KMF_ERR_MEMORY);

		valattr[0].pValue = keyvalue;
		rv = C_GetAttributeValue(hSession,
			(CK_OBJECT_HANDLE)pubKey,
			valattr, 1);
		if (rv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			free(keyvalue);
			return (KMF_ERR_BAD_PARAMETER);
		}

		IDInput.Data = keyvalue;
		IDInput.Length = valueLen;
	} else {
		return (KMF_ERR_BAD_PARAMETER);
	}

	if (params->keylabel != NULL &&
		strlen(params->keylabel)) {

		SETATTR(labelattr, 0, CKA_LABEL, params->keylabel,
			strlen(params->keylabel));

		/* Set the CKA_LABEL if one was indicated */
		if ((ckrv = C_SetAttributeValue(hSession, pubKey,
			labelattr, 1)) != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			rv = KMF_ERR_INTERNAL;
			goto cleanup;
		}
		if (pubkey != NULL) {
			pubkey->keylabel =
				(char *)strdup(params->keylabel);
			if (pubkey->keylabel == NULL) {
				rv = KMF_ERR_MEMORY;
				goto cleanup;
			}
		}
		if ((ckrv = C_SetAttributeValue(hSession, priKey,
			labelattr, 1)) != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			rv = KMF_ERR_INTERNAL;
			goto cleanup;
		}
		if (privkey != NULL) {
			privkey->keylabel =
				(char *)strdup(params->keylabel);
			if (privkey->keylabel == NULL) {
				rv = KMF_ERR_MEMORY;
				goto cleanup;
			}
		}
	}

	/* Now, assign a CKA_ID value so it can be searched */
	/* ID_Input was assigned above in the RSA or DSA keygen section */
	IDOutput.Data = (uchar_t *)IDHashData;
	IDOutput.Length = sizeof (IDHashData);

	rv = DigestData(hSession, &IDInput, &IDOutput);
	free(IDInput.Data);

	if (rv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		goto cleanup;
	}
	SETATTR(idattr, 0, CKA_ID, IDOutput.Data, IDOutput.Length);
	if ((ckrv = C_SetAttributeValue(hSession, pubKey,
			idattr, 1)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto cleanup;
	}
	if ((ckrv = C_SetAttributeValue(hSession, priKey,
			idattr, 1)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto cleanup;
	}

cleanup:
	if (rv != KMF_OK) {
		if (pubKey != CK_INVALID_HANDLE)
			(void) C_DestroyObject(hSession, pubKey);
		if (priKey != CK_INVALID_HANDLE)
			(void) C_DestroyObject(hSession, priKey);
		if (privkey) {
			privkey->keyp = NULL;
			if (privkey->keylabel)
				free(privkey->keylabel);
		}
		if (pubkey) {
			pubkey->keyp = NULL;
			if (pubkey->keylabel)
				free(pubkey->keylabel);
		}
	}
	return (rv);
}

KMF_RETURN
KMFPK11_DeleteKey(KMF_HANDLE_T handle, KMF_DELETEKEY_PARAMS *params,
	KMF_KEY_HANDLE *key, boolean_t destroy)
{
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	CK_RV ckrv = CKR_OK;
	KMF_RETURN rv = KMF_OK;

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (key == NULL || key->keyp == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (key->keyclass != KMF_ASYM_PUB &&
		key->keyclass != KMF_ASYM_PRI &&
		key->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	if (destroy) {
		rv = pk11_authenticate(handle, &params->cred);
		if (rv != KMF_OK) {
			return (rv);
		}
	}

	if (!key->israw && destroy)
		ckrv = C_DestroyObject(kmfh->pk11handle,
			(CK_OBJECT_HANDLE)key->keyp);

	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		/* Report authentication failures to the caller */
		if (ckrv == CKR_PIN_EXPIRED ||
		    ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_INTERNAL;
	}
	return (rv);

}

KMF_RETURN
KMFPK11_SignData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *keyp,
	KMF_OID *algOID,
	KMF_DATA *tobesigned,
	KMF_DATA *output)
{
	CK_RV			ckrv;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;
	CK_MECHANISM		mechanism;
	PKCS_ALGORITHM_MAP 	*pAlgMap;
	KMF_ALGORITHM_INDEX		AlgId;

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (keyp == NULL || algOID == NULL ||
	    tobesigned == NULL || output == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	/* These functions are available to the plugin from libkmf */
	AlgId = X509_AlgorithmOidToAlgId(algOID);
	if (AlgId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_PARAMETER);

	/* Map the Algorithm OID to a PKCS#11 mechanism */
	pAlgMap = PKCS_GetAlgorithmMap(KMF_ALGCLASS_SIGNATURE,
		AlgId, PKCS_GetDefaultSignatureMode(AlgId));

	if (pAlgMap == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	mechanism.mechanism = pAlgMap->pkcs_mechanism;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	ckrv = C_SignInit(hSession, &mechanism, (CK_OBJECT_HANDLE)keyp->keyp);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	ckrv = C_Sign(hSession,
		tobesigned->Data, tobesigned->Length,
		output->Data, (CK_ULONG *)&output->Length);

	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	return (KMF_OK);
}

KMF_RETURN
KMFPK11_GetErrorString(KMF_HANDLE_T handle, char **msgstr)
{
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	*msgstr = NULL;
	if (kmfh->lasterr.errcode != 0) {
		char *e = pkcs11_strerror(kmfh->lasterr.errcode);
		if (e == NULL || (*msgstr = (char *)strdup(e)) == NULL) {
			return (KMF_ERR_MEMORY);
		}
	}

	return (KMF_OK);
}

static CK_RV
getObjectKeytype(KMF_HANDLE_T handle, CK_OBJECT_HANDLE obj,
	CK_ULONG *keytype)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE templ;
	CK_ULONG len = sizeof (CK_ULONG);
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	templ.type = CKA_KEY_TYPE;
	templ.pValue = keytype;
	templ.ulValueLen = len;

	rv = C_GetAttributeValue(kmfh->pk11handle, obj, &templ, 1);

	return (rv);

}
static CK_RV
getObjectLabel(KMF_HANDLE_T handle, CK_OBJECT_HANDLE obj,
	char **outlabel)
{
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE templ;
	char	Label[BUFSIZ];
	CK_ULONG len = sizeof (Label);
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	(void) memset(Label, 0, len);
	templ.type = CKA_LABEL;
	templ.pValue = Label;
	templ.ulValueLen = len;

	rv = C_GetAttributeValue(kmfh->pk11handle, obj, &templ, 1);
	if (rv == CKR_OK) {
		*outlabel = (char *)strdup(Label);
	} else {
		*outlabel = NULL;
	}
	return (rv);
}

KMF_RETURN
KMFPK11_GetPrikeyByCert(KMF_HANDLE_T handle,
	KMF_CRYPTOWITHCERT_PARAMS *params,
	KMF_DATA *SignerCertData, KMF_KEY_HANDLE *key,
	KMF_KEY_ALG keytype)
{
	KMF_X509_SPKI *pubkey;
	KMF_X509_CERTIFICATE *SignerCert = NULL;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	KMF_RETURN rv = KMF_OK;
	CK_RV ckrv = CKR_OK;
	CK_ATTRIBUTE templ[4];
	CK_OBJECT_HANDLE pri_obj = CK_INVALID_HANDLE;
	CK_ULONG obj_count;
	CK_OBJECT_CLASS certClass = CKO_PRIVATE_KEY;
	CK_BBOOL true = TRUE;
	KMF_DATA Id = { NULL, 0 };

	/* Decode the signer cert so we can get the SPKI data */
	if ((rv = DerDecodeSignedCertificate(SignerCertData,
	    &SignerCert)) != KMF_OK)
		return (rv);

	/* Get the public key info from the signer certificate */
	pubkey = &SignerCert->certificate.subjectPublicKeyInfo;

	/* Generate an ID from the SPKI data */
	rv = GetIDFromSPKI(pubkey, &Id);

	if (rv != KMF_OK) {
		SET_ERROR(kmfh, rv);
		goto errout;
	}

	SETATTR(templ, 0, CKA_CLASS, &certClass, sizeof (certClass));
	SETATTR(templ, 1, CKA_TOKEN, &true, sizeof (true));
	SETATTR(templ, 2, CKA_PRIVATE, &true, sizeof (true));
	SETATTR(templ, 3, CKA_ID, Id.Data, Id.Length);

	rv = pk11_authenticate(handle, &params->cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	if ((ckrv = C_FindObjectsInit(kmfh->pk11handle, templ, 4)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto errout;
	}

	if ((rv = C_FindObjects(kmfh->pk11handle, &pri_obj, 1,
	    &obj_count)) != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto errout;
	}

	if (obj_count == 0) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_INTERNAL;
		goto errout;
	}

	key->kstype = KMF_KEYSTORE_PK11TOKEN;
	key->keyclass = KMF_ASYM_PRI;
	key->keyalg = keytype;
	key->keyp = (void *)pri_obj;

	(void) C_FindObjectsFinal(kmfh->pk11handle);

	ckrv = getObjectLabel(handle, (CK_OBJECT_HANDLE)key->keyp,
		&key->keylabel);

	if (ckrv != CKR_OK) {
		SET_ERROR(handle, ckrv);
		rv = KMF_ERR_INTERNAL;
	} else {
		rv = KMF_OK;
	}

	if (rv == KMF_OK && params->format == KMF_FORMAT_RAWKEY) {
		KMF_RAW_KEY_DATA *rkey = NULL;
		rv = keyObj2RawKey(handle, key, &rkey);
		if (rv == KMF_OK) {
			key->keyp = rkey;
			key->israw = TRUE;
		}
	}

errout:
	if (Id.Data != NULL)
		free(Id.Data);

	if (SignerCert != NULL) {
		KMF_FreeSignedCert(SignerCert);
		free(SignerCert);
	}
	return (rv);
}

KMF_RETURN
KMFPK11_DecryptData(KMF_HANDLE_T handle, KMF_KEY_HANDLE *key,
	KMF_OID *algOID, KMF_DATA *ciphertext,
	KMF_DATA *output)
{
	CK_RV			ckrv;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;
	CK_MECHANISM		mechanism;
	PKCS_ALGORITHM_MAP 	*pAlgMap;
	KMF_ALGORITHM_INDEX	AlgId;
	CK_ULONG out_len = 0, block_len = 0, total_decrypted = 0;
	uint8_t *in_data, *out_data;
	int i, blocks;
	CK_ATTRIBUTE ckTemplate[1];

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (key == NULL || algOID == NULL ||
	    ciphertext == NULL || output == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	AlgId = X509_AlgorithmOidToAlgId(algOID);
	if (AlgId == KMF_ALGID_NONE)
		return (KMF_ERR_BAD_PARAMETER);

	/* Map the Algorithm ID to a PKCS#11 mechanism */
	pAlgMap = PKCS_GetAlgorithmMap(KMF_ALGCLASS_SIGNATURE,
	    AlgId, PKCS_GetDefaultSignatureMode(AlgId));

	if (pAlgMap == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	mechanism.mechanism = pAlgMap->pkcs_mechanism;
	mechanism.pParameter = NULL;
	mechanism.ulParameterLen = 0;

	SETATTR(ckTemplate, 0, CKA_MODULUS, (CK_BYTE *)NULL,
	    sizeof (CK_ULONG));

	/* Get the modulus length */
	ckrv = C_GetAttributeValue(hSession,
	    (CK_OBJECT_HANDLE)key->keyp, ckTemplate, 1);

	if (ckrv != CKR_OK)  {
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	block_len = ckTemplate[0].ulValueLen;

	/* Compute the number of times to do single-part decryption */
	blocks = ciphertext->Length/block_len;

	out_data = output->Data;
	in_data = ciphertext->Data;
	out_len = block_len - 11;

	for (i = 0; i < blocks; i++) {
		ckrv = C_DecryptInit(hSession, &mechanism,
			(CK_OBJECT_HANDLE)key->keyp);

		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL);
		}

		ckrv = C_Decrypt(hSession, in_data, block_len,
		    out_data, (CK_ULONG *)&out_len);

		if (ckrv != CKR_OK) {
			SET_ERROR(kmfh, ckrv);
			return (KMF_ERR_INTERNAL);
		}

		out_data += out_len;
		total_decrypted += out_len;
		in_data += block_len;

	}

	output->Length = total_decrypted;
	return (KMF_OK);
}

static void
attr2bigint(CK_ATTRIBUTE_PTR attr, KMF_BIGINT *big)
{
	big->val = attr->pValue;
	big->len = attr->ulValueLen;
}


static KMF_RETURN
get_raw_rsa(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj, KMF_RAW_RSA_KEY *rawrsa)
{
	KMF_RETURN rv = KMF_OK;
	CK_SESSION_HANDLE sess = kmfh->pk11handle;
	CK_ATTRIBUTE	rsa_pri_attrs[8] = {
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 },
		{ CKA_PRIVATE_EXPONENT, NULL, 0 },	/* optional */
		{ CKA_PRIME_1, NULL, 0 },		/*  |  */
		{ CKA_PRIME_2, NULL, 0 },		/*  |  */
		{ CKA_EXPONENT_1, NULL, 0 },		/*  |  */
		{ CKA_EXPONENT_2, NULL, 0 },		/*  |  */
		{ CKA_COEFFICIENT, NULL, 0 }		/*  V  */
	    };
	CK_ULONG	count = sizeof (rsa_pri_attrs) / sizeof (CK_ATTRIBUTE);
	int		i;

	if ((rv = C_GetAttributeValue(sess, obj,
			rsa_pri_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, rv);
		return (KMF_ERR_INTERNAL);
	}

	/* Allocate memory for each attribute. */
	for (i = 0; i < count; i++) {
		if (rsa_pri_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    rsa_pri_attrs[i].ulValueLen == 0) {
			rsa_pri_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((rsa_pri_attrs[i].pValue =
		    malloc(rsa_pri_attrs[i].ulValueLen)) == NULL) {
			rv = KMF_ERR_MEMORY;
			goto end;
		}
	}
	/* Now that we have space, really get the attributes */
	if ((rv = C_GetAttributeValue(sess, obj,
			rsa_pri_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, rv);
		rv = KMF_ERR_INTERNAL;
		goto end;
	}
	i = 0;
	attr2bigint(&(rsa_pri_attrs[i++]), &rawrsa->mod);
	attr2bigint(&(rsa_pri_attrs[i++]), &rawrsa->pubexp);

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		attr2bigint(&(rsa_pri_attrs[i]), &rawrsa->priexp);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		attr2bigint(&(rsa_pri_attrs[i]), &rawrsa->prime1);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		attr2bigint(&(rsa_pri_attrs[i]), &rawrsa->prime2);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		attr2bigint(&(rsa_pri_attrs[i]), &rawrsa->exp1);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		attr2bigint(&(rsa_pri_attrs[i]), &rawrsa->exp2);
	i++;

	if (rsa_pri_attrs[i].ulValueLen != (CK_ULONG)-1 &&
	    rsa_pri_attrs[i].ulValueLen != 0)
		attr2bigint(&(rsa_pri_attrs[i]), &rawrsa->coef);
	i++;

end:
	if (rv != KMF_OK) {
		for (i = 0; i < count; i++) {
			if (rsa_pri_attrs[i].pValue != NULL)
				free(rsa_pri_attrs[i].pValue);
		}
		(void) memset(rawrsa, 0, sizeof (KMF_RAW_RSA_KEY));
	}
	return (rv);
}

static KMF_RETURN
get_raw_dsa(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj, KMF_RAW_DSA_KEY *rawdsa)
{
	KMF_RETURN rv = KMF_OK;
	CK_SESSION_HANDLE sess = kmfh->pk11handle;
	CK_ATTRIBUTE	dsa_pri_attrs[8] = {
		{ CKA_PRIME, NULL, 0 },
		{ CKA_SUBPRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		{ CKA_VALUE, NULL, 0 }
	};
	CK_ULONG	count = sizeof (dsa_pri_attrs) / sizeof (CK_ATTRIBUTE);
	int		i;

	if ((rv = C_GetAttributeValue(sess, obj,
		dsa_pri_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, rv);
		return (KMF_ERR_INTERNAL);
	}

	/* Allocate memory for each attribute. */
	for (i = 0; i < count; i++) {
		if (dsa_pri_attrs[i].ulValueLen == (CK_ULONG)-1 ||
		    dsa_pri_attrs[i].ulValueLen == 0) {
			dsa_pri_attrs[i].ulValueLen = 0;
			continue;
		}
		if ((dsa_pri_attrs[i].pValue =
		    malloc(dsa_pri_attrs[i].ulValueLen)) == NULL) {
			rv = KMF_ERR_MEMORY;
			goto end;
		}
	}
	if ((rv = C_GetAttributeValue(sess, obj,
		dsa_pri_attrs, count)) != CKR_OK) {
		SET_ERROR(kmfh, rv);
		rv = KMF_ERR_INTERNAL;
		goto end;
	}

	/* Fill in all the temp variables.  They are all required. */
	i = 0;
	attr2bigint(&(dsa_pri_attrs[i++]), &rawdsa->prime);
	attr2bigint(&(dsa_pri_attrs[i++]), &rawdsa->subprime);
	attr2bigint(&(dsa_pri_attrs[i++]), &rawdsa->base);
	attr2bigint(&(dsa_pri_attrs[i++]), &rawdsa->value);

end:
	if (rv != KMF_OK) {
		for (i = 0; i < count; i++) {
			if (dsa_pri_attrs[i].pValue != NULL)
				free(dsa_pri_attrs[i].pValue);
		}
		(void) memset(rawdsa, 0, sizeof (KMF_RAW_DSA_KEY));
	}
	return (rv);
}

static KMF_RETURN
get_raw_sym(KMF_HANDLE *kmfh, CK_OBJECT_HANDLE obj, KMF_RAW_SYM_KEY *rawsym)
{
	KMF_RETURN rv = KMF_OK;
	CK_RV	ckrv;
	CK_SESSION_HANDLE sess = kmfh->pk11handle;
	CK_ATTRIBUTE	sym_attr[1];
	CK_ULONG	value_len = 0;

	/* find the key length first */
	sym_attr[0].type = CKA_VALUE;
	sym_attr[0].pValue = NULL;
	sym_attr[0].ulValueLen = value_len;
	if ((ckrv = C_GetAttributeValue(sess, obj, sym_attr, 1)) != CKR_OK) {
		/*
		 * Don't return error if the key is sensitive, just
		 * don't return any raw data.  Operations like "list"
		 * need to succeed even if the raw data is not
		 * available.
		 */
		if (ckrv == CKR_ATTRIBUTE_SENSITIVE) {
			rawsym->keydata.val = NULL;
			rawsym->keydata.len = 0;
			return (CKR_OK);
		}
		SET_ERROR(kmfh, ckrv);
		return (KMF_ERR_INTERNAL);
	}

	/* Allocate memory for pValue */
	sym_attr[0].pValue = malloc(sym_attr[0].ulValueLen);
	if (sym_attr[0].pValue == NULL) {
		return (KMF_ERR_MEMORY);
	}

	/* get the key data */
	if ((rv = C_GetAttributeValue(sess, obj, sym_attr, 1)) != CKR_OK) {
		SET_ERROR(kmfh, rv);
		free(sym_attr[0].pValue);
		return (KMF_ERR_INTERNAL);
	}

	rawsym->keydata.val = sym_attr[0].pValue;
	rawsym->keydata.len = sym_attr[0].ulValueLen;
	return (rv);
}

static KMF_RETURN
keyObj2RawKey(KMF_HANDLE_T handle, KMF_KEY_HANDLE *inkey,
	KMF_RAW_KEY_DATA **outkey)
{
	KMF_RETURN rv = KMF_OK;
	KMF_RAW_KEY_DATA *rkey;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;

	rkey = malloc(sizeof (KMF_RAW_KEY_DATA));
	if (rkey == NULL)
		return (KMF_ERR_MEMORY);

	(void) memset(rkey, 0, sizeof (KMF_RAW_KEY_DATA));

	rkey->keytype = inkey->keyalg;

	if (inkey->keyalg == KMF_RSA) {
		rv = get_raw_rsa(kmfh, (CK_OBJECT_HANDLE)inkey->keyp,
			&rkey->rawdata.rsa);
	} else if (inkey->keyalg == KMF_DSA) {
		rv = get_raw_dsa(kmfh, (CK_OBJECT_HANDLE)inkey->keyp,
			&rkey->rawdata.dsa);
	} else if (inkey->keyalg == KMF_AES ||
	    inkey->keyalg == KMF_RC4 ||
	    inkey->keyalg == KMF_DES ||
	    inkey->keyalg == KMF_DES3) {
		rv = get_raw_sym(kmfh, (CK_OBJECT_HANDLE)inkey->keyp,
		    &rkey->rawdata.sym);
	} else {
		rv = KMF_ERR_BAD_PARAMETER;
	}

	if (rv == KMF_OK) {
		*outkey = rkey;
	} else if (rkey != NULL) {
		free(rkey);
		*outkey = NULL;
	}

	return (rv);
}


static KMF_RETURN
kmf2pk11keytype(KMF_KEY_ALG keyalg, CK_KEY_TYPE *type)
{
	switch (keyalg) {
	case KMF_RSA:
		*type = CKK_RSA;
		break;
	case KMF_DSA:
		*type = CKK_DSA;
		break;
	case KMF_AES:
		*type = CKK_AES;
		break;
	case KMF_RC4:
		*type = CKK_RC4;
		break;
	case KMF_DES:
		*type = CKK_DES;
		break;
	case KMF_DES3:
		*type = CKK_DES3;
		break;
	default:
		return (KMF_ERR_BAD_KEY_TYPE);
	}

	return (KMF_OK);
}

static int
IDStringToData(char *idstr, KMF_DATA *iddata)
{
	int len, i;
	char *iddup, *byte;
	uint_t lvalue;

	if (idstr == NULL || !strlen(idstr))
		return (-1);

	iddup = (char *)strdup(idstr);
	if (iddup == NULL)
		return (KMF_ERR_MEMORY);

	len = strlen(iddup) / 3  + 1;
	iddata->Data = malloc(len);
	if (iddata->Data == NULL)
		return (KMF_ERR_MEMORY);
	(void) memset(iddata->Data, 0, len);
	iddata->Length = len;

	byte = strtok(iddup, ":");
	if (byte == NULL) {
		free(iddup);
		free(iddata->Data);
		iddata->Data = NULL;
		iddata->Length = 0;
		return (-1);
	}

	i = 0;
	do {
		(void) sscanf(byte, "%x", &lvalue);
		iddata->Data[i++] = (uchar_t)(lvalue & 0x000000FF);
		byte = strtok(NULL, ":");
	} while (byte != NULL && i < len);

	iddata->Length = i;
	free(iddup);
	return (0);
}

KMF_RETURN
KMFPK11_FindKey(KMF_HANDLE_T handle, KMF_FINDKEY_PARAMS *parms,
	KMF_KEY_HANDLE *keys, uint32_t *numkeys)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	uint32_t want_keys, i;
	CK_RV ckrv;
	CK_ATTRIBUTE pTmpl[10];
	CK_OBJECT_CLASS class;
	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_ULONG alg;
	CK_BBOOL is_token;

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (parms == NULL || numkeys == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (numkeys != NULL && *numkeys > 0)
		want_keys = *numkeys;
	else
		want_keys = MAXINT; /* count them all */

	if (parms->keyclass == KMF_ASYM_PUB) {
		class = CKO_PUBLIC_KEY;
		is_token = false;
	} else if (parms->keyclass == KMF_ASYM_PRI) {
		class = CKO_PRIVATE_KEY;
		is_token = true;
	} else if (parms->keyclass == KMF_SYMMETRIC) {
		class = CKO_SECRET_KEY;
		is_token = true;
	} else {
		return (KMF_ERR_BAD_KEY_CLASS);
	}

	i = 0;
	pTmpl[i].type = CKA_TOKEN;
	pTmpl[i].pValue = &is_token;
	pTmpl[i].ulValueLen = sizeof (CK_BBOOL);
	i++;

	pTmpl[i].type = CKA_CLASS;
	pTmpl[i].pValue = &class;
	pTmpl[i].ulValueLen = sizeof (class);
	i++;

	if (parms->findLabel != NULL && strlen(parms->findLabel)) {
		pTmpl[i].type = CKA_LABEL;
		pTmpl[i].pValue = parms->findLabel;
		pTmpl[i].ulValueLen = strlen(parms->findLabel);
		i++;
	}

	if (parms->keytype != 0) {
		rv = kmf2pk11keytype(parms->keytype, &alg);
		if (rv != KMF_OK) {
			return (KMF_ERR_BAD_KEY_TYPE);
		}
		pTmpl[i].type = CKA_KEY_TYPE;
		pTmpl[i].pValue = &alg;
		pTmpl[i].ulValueLen = sizeof (alg);
		i++;
	}

	if (parms->idstr != NULL) {
		KMF_DATA iddata = { NULL, 0 };

		/*
		 * ID String parameter is assumed to be of form:
		 * XX:XX:XX:XX:XX ... :XX
		 * where XX is a hex number.
		 *
		 * We must convert this back to binary in order to
		 * use it in a search.
		 */
		rv = IDStringToData(parms->idstr, &iddata);
		if (rv == KMF_OK) {
			pTmpl[i].type = CKA_ID;
			pTmpl[i].pValue = iddata.Data;
			pTmpl[i].ulValueLen = iddata.Length;
			i++;
		} else {
			return (rv);
		}
	}

	if (parms->pkcs11parms.private) {
		pTmpl[i].type = CKA_PRIVATE;
		pTmpl[i].pValue = &true;
		pTmpl[i].ulValueLen = sizeof (true);
		i++;
	}

	if (is_token) {
		rv = pk11_authenticate(handle, &parms->cred);
		if (rv != KMF_OK) {
			return (rv);
		}
	}

	ckrv = C_FindObjectsInit(kmfh->pk11handle, pTmpl, i);
	if (ckrv == CKR_OK) {
		CK_ULONG obj_count, n = 0;
		while (ckrv == CKR_OK && n < want_keys) {
			CK_OBJECT_HANDLE hObj;

			ckrv = C_FindObjects(kmfh->pk11handle, &hObj,
				1, &obj_count);
			if (ckrv == CKR_OK && obj_count == 1) {
				if (keys != NULL) {
					CK_ULONG keytype;
					keys[n].kstype = KMF_KEYSTORE_PK11TOKEN;
					keys[n].keyclass = parms->keyclass;
					keys[n].israw = FALSE;
					keys[n].keyp = (void *)hObj;

					ckrv = getObjectKeytype(handle,
						(CK_OBJECT_HANDLE)keys[n].keyp,
						&keytype);
					if (ckrv != CKR_OK)
						goto end;

					ckrv = getObjectLabel(handle,
						(CK_OBJECT_HANDLE)keys[n].keyp,
						&(keys[n].keylabel));
					if (ckrv != CKR_OK)
						goto end;

					if (keytype == CKK_RSA)
						keys[n].keyalg = KMF_RSA;
					else if (keytype == CKK_DSA)
						keys[n].keyalg = KMF_DSA;
					else if (keytype == CKK_AES)
						keys[n].keyalg = KMF_AES;
					else if (keytype == CKK_RC4)
						keys[n].keyalg = KMF_RC4;
					else if (keytype == CKK_DES)
						keys[n].keyalg = KMF_DES;
					else if (keytype == CKK_DES3)
						keys[n].keyalg = KMF_DES3;

				}
				n++;
			} else {
				break;
			}
		}
		ckrv = C_FindObjectsFinal(kmfh->pk11handle);

		/* "numkeys" indicates the number that were actually found */
		*numkeys = n;
	}
	if (ckrv == KMF_OK && keys != NULL && (*numkeys) > 0 &&
		parms->format == KMF_FORMAT_RAWKEY) {
		/* Convert keys to "rawkey" format */
		for (i = 0; i < (*numkeys); i++) {
			KMF_RAW_KEY_DATA *rkey = NULL;
			rv = keyObj2RawKey(handle, &keys[i], &rkey);
			if (rv == KMF_OK) {
				keys[i].keyp = rkey;
				keys[i].israw = TRUE;
			} else {
				break;
			}
		}
	}
end:
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		/* Report authentication failures to the caller */
		if (ckrv == CKR_USER_NOT_LOGGED_IN ||
		    ckrv == CKR_PIN_INCORRECT ||
		    ckrv == CKR_PIN_INVALID ||
		    ckrv == CKR_PIN_EXPIRED ||
		    ckrv == CKR_PIN_LOCKED ||
		    ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_INTERNAL;
	} else if ((*numkeys) == 0) {
		rv = KMF_ERR_KEY_NOT_FOUND;
	}

	return (rv);
}

static char *
convertDate(char *fulldate)
{
	struct tm tms;
	char newtime[9];

	(void) strptime(fulldate, "%b %d %T %Y %Z", &tms);

	if (tms.tm_year < 69)
		tms.tm_year += 100;

	(void) strftime(newtime, sizeof (newtime), "m%d", &tms);

	newtime[8] = 0;

	/* memory returned must be freed by the caller */
	return ((char *)strdup(newtime));
}

KMF_RETURN
KMFPK11_StorePrivateKey(KMF_HANDLE_T handle, KMF_STOREKEY_PARAMS *params,
	KMF_RAW_KEY_DATA *rawkey)
{
	KMF_RETURN rv = KMF_OK;
	KMF_HANDLE *kmfh = (KMF_HANDLE *)handle;
	int i;
	CK_RV		ckrv = CKR_OK;
	CK_ATTRIBUTE	templ[32];
	CK_OBJECT_HANDLE keyobj;
	CK_KEY_TYPE	keytype;
	CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
	CK_BBOOL	cktrue = TRUE;
	CK_DATE		startdate, enddate;
	KMF_DATA	id = {NULL, 0};
	KMF_DATA	subject = {NULL, 0};
	KMF_X509EXT_KEY_USAGE kuext;
	KMF_X509_CERTIFICATE *x509 = NULL;
	CK_BBOOL	kufound;
	char		*notbefore = NULL, *start = NULL;
	char		*notafter = NULL, *end = NULL;

	if (!kmfh)
		return (KMF_ERR_UNINITIALIZED); /* Plugin Not Initialized */

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (params == NULL || params->certificate == NULL ||
		rawkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	if (rawkey->keytype == KMF_RSA)
		keytype = CKK_RSA;
	else if (rawkey->keytype == KMF_DSA)
		keytype = CKK_DSA;
	else
		return (KMF_ERR_BAD_PARAMETER);

	rv = pk11_authenticate(handle, &params->cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	id.Data = NULL;
	id.Length = 0;
	rv = KMF_GetCertIDData(params->certificate, &id);
	if (rv != KMF_OK) {
		goto cleanup;
	}

	rv = DerDecodeSignedCertificate(
		(const KMF_DATA *)params->certificate, &x509);
	if (rv != KMF_OK) {
		goto cleanup;
	}

	rv = DerEncodeName(&x509->certificate.subject, &subject);
	if (rv != KMF_OK) {
		goto cleanup;
	}

	rv = KMF_GetCertStartDateString(handle, params->certificate,
		&notbefore);
	if (rv != KMF_OK) {
		goto cleanup;
	}
	start = convertDate(notbefore);

	rv = KMF_GetCertEndDateString(handle, params->certificate,
		&notafter);
	if (rv != KMF_OK) {
		goto cleanup;
	}
	end = convertDate(notafter);

	if ((rv = KMF_GetCertKeyUsageExt(params->certificate, &kuext))
		!= KMF_OK && rv != KMF_ERR_EXTENSION_NOT_FOUND)
		goto cleanup;

	kufound = (rv == KMF_OK);
	rv = KMF_OK; /* reset if we got KMF_ERR_EXTENSION_NOT_FOUND above */

	i = 0;
	SETATTR(templ, i, CKA_CLASS, &oClass, sizeof (CK_OBJECT_CLASS)); i++;
	SETATTR(templ, i, CKA_KEY_TYPE, &keytype, sizeof (keytype)); i++;
	SETATTR(templ, i, CKA_TOKEN, &cktrue, sizeof (cktrue)); i++;
	SETATTR(templ, i, CKA_PRIVATE, &cktrue, sizeof (cktrue)); i++;
	SETATTR(templ, i, CKA_SUBJECT, subject.Data, subject.Length); i++;

	/*
	 * Only set the KeyUsage stuff if the KU extension was present.
	 */
	if (kufound) {
		CK_BBOOL	condition;

		condition = (kuext.KeyUsageBits & KMF_keyEncipherment) ?
			B_TRUE : B_FALSE;
		SETATTR(templ, i, CKA_UNWRAP, &condition,
			sizeof (CK_BBOOL)); i++;
		condition = (kuext.KeyUsageBits & KMF_dataEncipherment) ?
			B_TRUE : B_FALSE;
		SETATTR(templ, i, CKA_DECRYPT, &condition,
			sizeof (CK_BBOOL)); i++;
		condition = (kuext.KeyUsageBits & KMF_digitalSignature) ?
			B_TRUE : B_FALSE;
		SETATTR(templ, i, CKA_SIGN, &condition,
			sizeof (CK_BBOOL)); i++;
		condition = (kuext.KeyUsageBits & KMF_digitalSignature) ?
			B_TRUE : B_FALSE;
		SETATTR(templ, i, CKA_SIGN_RECOVER, &condition,
			sizeof (CK_BBOOL)); i++;
	}
	if (params->label != NULL) {
		SETATTR(templ, i, CKA_LABEL, params->label,
			strlen(params->label));
		i++;
	}
	if (id.Data != NULL &&
		id.Data != NULL && id.Length > 0) {
		SETATTR(templ, i, CKA_ID, id.Data, id.Length);
		i++;
	}
	if (start != NULL) {
		/*
		 * This make some potentially dangerous assumptions:
		 *  1. that the startdate in the parameter block is
		 * properly formatted as YYYYMMDD
		 *  2. That the CK_DATE structure is always the same.
		 */
		(void) memcpy(&startdate, start, sizeof (CK_DATE));
		SETATTR(templ, i, CKA_START_DATE, &startdate,
			sizeof (startdate));
		i++;
	}
	if (end != NULL) {
		(void) memcpy(&enddate, end, sizeof (CK_DATE));
		SETATTR(templ, i, CKA_END_DATE, &enddate, sizeof (enddate));
		i++;
	}
	if (keytype == CKK_RSA) {
		SETATTR(templ, i, CKA_MODULUS,
			rawkey->rawdata.rsa.mod.val,
			rawkey->rawdata.rsa.mod.len);
		i++;
		SETATTR(templ, i, CKA_PUBLIC_EXPONENT,
			rawkey->rawdata.rsa.pubexp.val,
			rawkey->rawdata.rsa.pubexp.len);
		i++;
		if (rawkey->rawdata.rsa.priexp.val != NULL) {
			SETATTR(templ, i, CKA_PRIVATE_EXPONENT,
				rawkey->rawdata.rsa.priexp.val,
				rawkey->rawdata.rsa.priexp.len);
			i++;
		}
		if (rawkey->rawdata.rsa.prime1.val != NULL) {
			SETATTR(templ, i, CKA_PRIME_1,
				rawkey->rawdata.rsa.prime1.val,
				rawkey->rawdata.rsa.prime1.len);
			i++;
		}
		if (rawkey->rawdata.rsa.prime2.val != NULL) {
			SETATTR(templ, i, CKA_PRIME_2,
				rawkey->rawdata.rsa.prime2.val,
				rawkey->rawdata.rsa.prime2.len);
			i++;
		}
		if (rawkey->rawdata.rsa.exp1.val != NULL) {
			SETATTR(templ, i, CKA_EXPONENT_1,
				rawkey->rawdata.rsa.exp1.val,
				rawkey->rawdata.rsa.exp1.len);
			i++;
		}
		if (rawkey->rawdata.rsa.exp2.val != NULL) {
			SETATTR(templ, i, CKA_EXPONENT_2,
				rawkey->rawdata.rsa.exp2.val,
				rawkey->rawdata.rsa.exp2.len);
			i++;
		}
		if (rawkey->rawdata.rsa.coef.val != NULL) {
			SETATTR(templ, i, CKA_COEFFICIENT,
				rawkey->rawdata.rsa.coef.val,
				rawkey->rawdata.rsa.coef.len);
			i++;
		}
	} else {
		SETATTR(templ, i, CKA_PRIME,
			rawkey->rawdata.dsa.prime.val,
			rawkey->rawdata.dsa.prime.len);
		i++;
		SETATTR(templ, i, CKA_SUBPRIME,
			rawkey->rawdata.dsa.subprime.val,
			rawkey->rawdata.dsa.subprime.len);
		i++;
		SETATTR(templ, i, CKA_BASE,
			rawkey->rawdata.dsa.base.val,
			rawkey->rawdata.dsa.base.len);
		i++;
		SETATTR(templ, i, CKA_VALUE,
			rawkey->rawdata.dsa.value.val,
			rawkey->rawdata.dsa.value.len);
		i++;
	}

	ckrv = C_CreateObject(kmfh->pk11handle, templ, i, &keyobj);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);

		/* Report authentication failures to the caller */
		if (ckrv == CKR_USER_NOT_LOGGED_IN ||
		    ckrv == CKR_PIN_INCORRECT ||
		    ckrv == CKR_PIN_INVALID ||
		    ckrv == CKR_PIN_EXPIRED ||
		    ckrv == CKR_PIN_LOCKED ||
		    ckrv == CKR_SESSION_READ_ONLY)
			rv = KMF_ERR_AUTH_FAILED;
		else
			rv = KMF_ERR_INTERNAL;
	}
cleanup:
	KMF_FreeData(&id);
	KMF_FreeData(&subject);
	KMF_FreeSignedCert(x509);
	free(x509);

	return (rv);
}

KMF_RETURN
KMFPK11_CreateSymKey(KMF_HANDLE_T handle, KMF_CREATESYMKEY_PARAMS *params,
	KMF_KEY_HANDLE *symkey)
{
	KMF_RETURN		rv = KMF_OK;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;
	CK_RV			ckrv;
	CK_SESSION_HANDLE	hSession = kmfh->pk11handle;
	CK_OBJECT_HANDLE	keyhandle;
	CK_MECHANISM		keyGenMech;
	CK_OBJECT_CLASS		class = CKO_SECRET_KEY;
	CK_ULONG		secKeyType;
	CK_ULONG		secKeyLen;	/* for RC4 and AES */
	CK_BBOOL		true = TRUE;
	CK_BBOOL		false = FALSE;
	CK_ATTRIBUTE		templ[15];
	int i;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (params == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	keyGenMech.pParameter = NULL_PTR;
	keyGenMech.ulParameterLen = 0;
	switch (params->keytype) {
	case KMF_AES:
		keyGenMech.mechanism = CKM_AES_KEY_GEN;
		secKeyType = CKK_AES;
		break;
	case KMF_RC4:
		keyGenMech.mechanism = CKM_RC4_KEY_GEN;
		secKeyType = CKK_RC4;
		break;
	case KMF_DES:
		keyGenMech.mechanism = CKM_DES_KEY_GEN;
		secKeyType = CKK_DES;
		break;
	case KMF_DES3:
		keyGenMech.mechanism = CKM_DES3_KEY_GEN;
		secKeyType = CKK_DES3;
		break;
	default:
		return (KMF_ERR_BAD_KEY_TYPE);
	}

	i = 0;
	SETATTR(templ, i, CKA_CLASS, &class, sizeof (class));
	i++;
	SETATTR(templ, i, CKA_KEY_TYPE, &secKeyType, sizeof (secKeyType));
	i++;

	if (params->keytype == KMF_AES || params->keytype == KMF_RC4) {
		if ((params->keylength % 8) != 0) {
			return (KMF_ERR_BAD_KEY_SIZE);
		}
		secKeyLen = params->keylength/8;  /* in bytes for RC4/AES */
		SETATTR(templ, i, CKA_VALUE_LEN, &secKeyLen,
		    sizeof (secKeyLen));
		i++;
	}

	if (params->keylabel != NULL) {
		SETATTR(templ, i, CKA_LABEL, params->keylabel,
		    strlen(params->keylabel));
		i++;
	}

	if (params->pkcs11parms.sensitive == B_TRUE) {
		SETATTR(templ, i, CKA_SENSITIVE, &true, sizeof (true));
	} else {
		SETATTR(templ, i, CKA_SENSITIVE, &false, sizeof (false));
	}
	i++;

	if (params->pkcs11parms.not_extractable == B_TRUE) {
		SETATTR(templ, i, CKA_EXTRACTABLE, &false, sizeof (false));
	} else {
		SETATTR(templ, i, CKA_EXTRACTABLE, &true, sizeof (true));
	}
	i++;

	SETATTR(templ, i, CKA_TOKEN, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_PRIVATE, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_ENCRYPT, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_DECRYPT, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_SIGN, &true, sizeof (true));
	i++;
	SETATTR(templ, i, CKA_VERIFY, &true, sizeof (true));
	i++;

	rv = pk11_authenticate(handle, &params->cred);
	if (rv != KMF_OK) {
		return (rv);
	}

	ckrv = C_GenerateKey(hSession, &keyGenMech, templ, i, &keyhandle);
	if (ckrv != CKR_OK) {
		SET_ERROR(kmfh, ckrv);
		rv = KMF_ERR_KEYGEN_FAILED;
		goto out;
	}

	symkey->kstype = KMF_KEYSTORE_PK11TOKEN;
	symkey->keyalg = params->keytype;
	symkey->keyclass = KMF_SYMMETRIC;
	symkey->israw = FALSE;
	symkey->keyp = (void *)keyhandle;

out:
	return (rv);
}


KMF_RETURN
KMFPK11_GetSymKeyValue(KMF_HANDLE_T handle, KMF_KEY_HANDLE *symkey,
    KMF_RAW_SYM_KEY *rkey)
{
	KMF_RETURN		rv = KMF_OK;
	KMF_HANDLE		*kmfh = (KMF_HANDLE *)handle;

	if (kmfh == NULL)
		return (KMF_ERR_UNINITIALIZED);

	if (kmfh->pk11handle == CK_INVALID_HANDLE)
		return (KMF_ERR_NO_TOKEN_SELECTED);

	if (symkey == NULL || rkey == NULL)
		return (KMF_ERR_BAD_PARAMETER);
	else if (symkey->keyclass != KMF_SYMMETRIC)
		return (KMF_ERR_BAD_KEY_CLASS);

	if (symkey->israw) {
		KMF_RAW_KEY_DATA *rawkey = (KMF_RAW_KEY_DATA *)symkey->keyp;

		if (rawkey == NULL ||
		    rawkey->rawdata.sym.keydata.val == NULL ||
		    rawkey->rawdata.sym.keydata.len == 0)
			return (KMF_ERR_BAD_KEYHANDLE);

		rkey->keydata.len = rawkey->rawdata.sym.keydata.len;
		if ((rkey->keydata.val = malloc(rkey->keydata.len)) == NULL)
			return (KMF_ERR_MEMORY);
		(void) memcpy(rkey->keydata.val,
			rawkey->rawdata.sym.keydata.val, rkey->keydata.len);
	} else {
		rv = get_raw_sym(kmfh, (CK_OBJECT_HANDLE)symkey->keyp, rkey);
	}

	return (rv);
}

KMF_RETURN
KMFPK11_SetTokenPin(KMF_HANDLE_T handle, KMF_SETPIN_PARAMS *params,
	KMF_CREDENTIAL *newpin)
{
	KMF_RETURN	ret = KMF_OK;
	CK_RV		rv = CKR_OK;
	KMF_HANDLE	*kmfh = (KMF_HANDLE *)handle;
	CK_SESSION_HANDLE	session = NULL;

	if (handle == NULL || params == NULL || newpin == NULL)
		return (KMF_ERR_BAD_PARAMETER);

	rv = C_OpenSession(params->pkcs11parms.slot,
		CKF_SERIAL_SESSION | CKF_RW_SESSION,
		NULL, NULL, &session);
	if (rv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		ret = KMF_ERR_UNINITIALIZED;
		goto end;
	}

	rv = C_SetPIN(session,
		(CK_BYTE *)params->cred.cred, params->cred.credlen,
		(CK_BYTE *)newpin->cred, newpin->credlen);

	if (rv != CKR_OK) {
		SET_ERROR(kmfh, rv);
		if (rv == CKR_PIN_INCORRECT ||
		    rv == CKR_PIN_INVALID ||
		    rv == CKR_PIN_EXPIRED ||
		    rv == CKR_PIN_LOCKED)
			ret = KMF_ERR_AUTH_FAILED;
		else
			ret = KMF_ERR_INTERNAL;
	}
end:
	if (session != NULL)
		(void) C_CloseSession(session);
	return (ret);
}
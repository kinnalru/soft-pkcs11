/*
 * Copyright (c) 2006, Stockholms universitet
 * (Stockholm University, Stockholm Sweden)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the university nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id: test_soft_pkcs11.c,v 1.5 2006/01/11 12:41:18 lha Exp $ */

#include "locl.h"

static CK_RV
find_object(CK_SESSION_HANDLE session, 
	    char *id,
	    CK_OBJECT_CLASS key_class, 
	    CK_OBJECT_HANDLE_PTR object)
{
    CK_ULONG object_count;
    CK_RV ret;
    CK_ATTRIBUTE search_data[] = {
	{CKA_ID, id, 0 },
	{CKA_CLASS, &key_class, sizeof(key_class)}
    };
    CK_ULONG num_search_data = sizeof(search_data)/sizeof(search_data[0]);

    search_data[0].ulValueLen = strlen(id);

    ret = C_FindObjectsInit(session, search_data, num_search_data);
    if (ret != CKR_OK)
	return ret;

    ret = C_FindObjects(session, object, 1, &object_count);
    if (ret != CKR_OK)
	return ret;
    if (object_count == 0) {
	printf("found no object\n");
	return 1;
    }

    ret = C_FindObjectsFinal(session);
    if (ret != CKR_OK)
	return ret;

    return CKR_OK;
}

static char *sighash = "hej";
static char signature[1024];
static char outdata[1024];


int
main(int argc, char **argv)
{
    CK_SLOT_ID_PTR slot_ids;
    CK_SLOT_ID slot;
    CK_ULONG num_slots;
    CK_RV ret;
    CK_SLOT_INFO slot_info;
    CK_TOKEN_INFO token_info;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE public, private;

    C_Initialize(NULL_PTR);

    ret = C_GetSlotList(FALSE, NULL, &num_slots);
    if (ret)
	return 1;

    if (num_slots == 0)
	return 1;

    if ((slot_ids = calloc(1, num_slots * sizeof(*slot_ids))) == NULL)
	return 1;

    ret = C_GetSlotList(FALSE, slot_ids, &num_slots);
    if (ret)
	return 1;

    slot = slot_ids[0];
    free(slot_ids);

    ret = C_GetSlotInfo(slot, &slot_info);
    if (ret)
	return 1;

    if ((slot_info.flags & CKF_TOKEN_PRESENT) == 0)
	return 1;

    ret = C_GetTokenInfo(slot, &token_info);
    if (ret)
	return 1;

    if (token_info.flags & CKF_LOGIN_REQUIRED) {
	printf("login required, no C_Login support yet");
	return 1;
    }

    ret = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &session);
    if (ret != CKR_OK)
	return 1;
    
    ret = find_object(session, "cert", CKO_PUBLIC_KEY, &public);
    if (ret)
	return 1;
    ret = find_object(session, "cert", CKO_PRIVATE_KEY, &private);
    if (ret)
	return 1;

    {
	CK_ULONG ck_sigsize;
	CK_MECHANISM mechanism;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	ret = C_SignInit(session, &mechanism, private);
	if (ret != CKR_OK)
	    return 1;
	
	ck_sigsize = sizeof(signature);
	ret = C_Sign(session, (CK_BYTE *)sighash, strlen(sighash),
		     (CK_BYTE *)signature, &ck_sigsize);
	if (ret != CKR_OK) {
	    printf("message: %d\n", ret);
	    return 1;
	}

	ret = C_VerifyInit(session, &mechanism, public);
	if (ret != CKR_OK)
	    return 1;

	ret = C_Verify(session, (CK_BYTE *)signature, ck_sigsize, 
		       (CK_BYTE *)sighash, strlen(sighash));
	if (ret != CKR_OK) {
	    printf("message: %d\n", ret);
	    return 1;
	}
    }

    {
	CK_ULONG ck_sigsize, outsize;
	CK_MECHANISM mechanism;

	memset(&mechanism, 0, sizeof(mechanism));
	mechanism.mechanism = CKM_RSA_PKCS;

	ret = C_EncryptInit(session, &mechanism, public);
	if (ret != CKR_OK)
	    return 1;
	
	ck_sigsize = sizeof(signature);
	ret = C_Encrypt(session, (CK_BYTE *)sighash, strlen(sighash),
		     (CK_BYTE *)signature, &ck_sigsize);
	if (ret != CKR_OK) {
	    printf("message: %d\n", ret);
	    return 1;
	}

	ret = C_DecryptInit(session, &mechanism, private);
	if (ret != CKR_OK)
	    return 1;

	outsize = sizeof(outdata);
	ret = C_Decrypt(session, (CK_BYTE *)signature, ck_sigsize, 
		       (CK_BYTE *)outdata, &outsize);
	if (ret != CKR_OK) {
	    printf("message: %d\n", ret);
	    return 1;
	}

	if (memcmp(sighash, outdata, strlen(sighash)) != 0)
	    return 1;
    }

    ret = C_CloseSession(session);
    if (ret != CKR_OK)
	return 1;

    C_Finalize(NULL_PTR);

    return 0;
}

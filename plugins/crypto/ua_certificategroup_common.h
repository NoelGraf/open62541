/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 */

#ifndef CERTIFICATEGROUP_COMMON_H
#define CERTIFICATEGROUP_COMMON_H

#include <open62541/plugin/certificategroup.h>
#include <open62541/types_generated_handling.h>

_UA_BEGIN_DECLS

typedef struct FileCertStore FileCertStore;

struct FileCertStore {
    char *trustedCertDir;
    size_t trustedCertDirLen;
    char *trustedCrlDir;
    size_t trustedCrlDirLen;
    char *trustedIssuerCertDir;
    size_t trustedIssuerCertDirLen;
    char *trustedIssuerCrlDir;
    size_t trustedIssuerCrlDirLen;
    char *rejectedCertDir;
    size_t rejectedCertDirLen;
    char *rootDir;
    size_t rootDirLen;
};

UA_StatusCode
FileCertStore_removeFromTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList);

UA_StatusCode
FileCertStore_getTrustList(UA_CertificateGroup *certGroup, UA_TrustListDataType *trustList);

UA_StatusCode
FileCertStore_setTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList);

UA_StatusCode
FileCertStore_addToTrustList(UA_CertificateGroup *certGroup, const UA_TrustListDataType *trustList);

UA_StatusCode
FileCertStore_getRejectedList(UA_CertificateGroup *certGroup, UA_ByteString **rejectedList, size_t *rejectedListSize);

UA_StatusCode
FileCertStore_addToRejectedList(UA_CertificateGroup *certGroup, const UA_ByteString *certificate);

void
FileCertStore_clear(UA_CertificateGroup *certGroup);

UA_StatusCode
FileCertStore_createRootDirectory(UA_String *directory,
                                  const UA_NodeId *certificateGroupId,
                                  char** rootDir,
                                  size_t* rootDirLen);

UA_StatusCode
FileCertStore_setupStorePath(char *directory, char *cwd, size_t cwdLen, char **out);

_UA_END_DECLS

#endif /* CERTIFICATEGROUP_COMMON_H */

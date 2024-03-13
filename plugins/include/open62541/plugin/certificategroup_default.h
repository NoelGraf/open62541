/* This work is licensed under a Creative Commons CCZero 1.0 Universal License.
 * See http://creativecommons.org/publicdomain/zero/1.0/ for more information.
 *
 *    Copyright 2018 (c) Mark Giraud, Fraunhofer IOSB
 *    Copyright 2019 (c) Kalycito Infotech Private Limited
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 */

#ifndef UA_CERTIFICATEGROUP_CERTIFICATE_H_
#define UA_CERTIFICATEGROUP_CERTIFICATE_H_

#include <open62541/plugin/certificategroup.h>

_UA_BEGIN_DECLS

/* Default implementation that accepts all certificates */
UA_EXPORT void
UA_CertificateGroup_AcceptAll(UA_CertificateGroup *certGroup);

UA_EXPORT UA_StatusCode
UA_CertificateGroup_Filestore(UA_CertificateGroup *certGroup,
                              UA_NodeId *certificateGroupId,
                              const UA_String *storePath);

_UA_END_DECLS

#endif /* UA_CERTIFICATEGROUP_CERTIFICATE_H_ */

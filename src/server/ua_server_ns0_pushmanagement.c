/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 */

#include "ua_server_internal.h"

#ifdef UA_ENABLE_ENCRYPTION

static UA_StatusCode
writeGDSNs0VariableArray(UA_Server *server, const UA_NodeId id, void *v,
                         size_t length, const UA_DataType *type) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_Variant var;
    UA_Variant_init(&var);
    UA_Variant_setArray(&var, v, length, type);
    return writeValueAttribute(server, id, &var);
}

static UA_StatusCode
writeGDSNs0Variable(UA_Server *server, const UA_NodeId id,
                    void *v, const UA_DataType *type) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);
    UA_Variant var;
    UA_Variant_init(&var);
    UA_Variant_setScalar(&var, v, type);
    return writeValueAttribute(server, id, &var);
}

static UA_StatusCode
updateCertificate(UA_Server *server,
                  const UA_NodeId *sessionId, void *sessionHandle,
                  const UA_NodeId *methodId, void *methodContext,
                  const UA_NodeId *objectId, void *objectContext,
                  size_t inputSize, const UA_Variant *input,
                  size_t outputSize, UA_Variant *output) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /*check for input types*/
    if(!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_NODEID]) || /*CertificateGroupId*/
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_NODEID]) || /*CertificateTypeId*/
       !UA_Variant_hasScalarType(&input[2], &UA_TYPES[UA_TYPES_BYTESTRING]) || /*Certificate*/
       !UA_Variant_hasArrayType(&input[3], &UA_TYPES[UA_TYPES_BYTESTRING]) || /*IssuerCertificates*/
       !UA_Variant_hasScalarType(&input[4], &UA_TYPES[UA_TYPES_STRING]) || /*PrivateKeyFormat*/
       !UA_Variant_hasScalarType(&input[5], &UA_TYPES[UA_TYPES_BYTESTRING])) /*PrivateKey*/
        return UA_STATUSCODE_BADTYPEMISMATCH;

    UA_NodeId *certificateGroupId = (UA_NodeId *)input[0].data;
    UA_NodeId *certificateTypeId = (UA_NodeId *)input[1].data;
    UA_ByteString *certificate = (UA_ByteString *)input[2].data;
    UA_ByteString *issuerCertificates = ((UA_ByteString *)input[3].data);
    size_t issuerCertificatesSize = input[3].arrayLength;
    UA_String *privateKeyFormat = (UA_String *)input[4].data;
    UA_ByteString *privateKey = (UA_ByteString *)input[5].data;

    retval = UA_Server_updateCertificate(server, certificateGroupId, certificateTypeId,
                                         certificate, issuerCertificates, issuerCertificatesSize,
                                         privateKey, privateKeyFormat);

    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Output arg, indicates that the ApplyChanges Method shall be called before the new Certificate will be used. */
    UA_Boolean applyChangesRequired = false;
    UA_Variant_setScalarCopy(output, &applyChangesRequired, &UA_TYPES[UA_TYPES_BOOLEAN]);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
createSigningRequest(UA_Server *server,
                     const UA_NodeId *sessionId, void *sessionHandle,
                     const UA_NodeId *methodId, void *methodContext,
                     const UA_NodeId *objectId, void *objectContext,
                     size_t inputSize, const UA_Variant *input,
                     size_t outputSize, UA_Variant *output) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /*check for input types*/
    if(!UA_Variant_hasScalarType(&input[0], &UA_TYPES[UA_TYPES_NODEID]) || /*CertificateGroupId*/
       !UA_Variant_hasScalarType(&input[1], &UA_TYPES[UA_TYPES_NODEID]) || /*CertificateTypeId*/
       !UA_Variant_hasScalarType(&input[2], &UA_TYPES[UA_TYPES_STRING]) || /*SubjectName*/
       !UA_Variant_hasScalarType(&input[3], &UA_TYPES[UA_TYPES_BOOLEAN]) || /*RegeneratePrivateKey*/
       !UA_Variant_hasScalarType(&input[4], &UA_TYPES[UA_TYPES_BYTESTRING]))  /*Nonce*/
        return UA_STATUSCODE_BADTYPEMISMATCH;

    UA_NodeId *certificateGroupId = (UA_NodeId *)input[0].data;
    UA_NodeId *certificateTypeId = (UA_NodeId *)input[1].data;
    UA_String *subjectName = (UA_String *)input[2].data;
    UA_Boolean *regenerateKey = ((UA_Boolean *)input[3].data);
    UA_ByteString *nonce = (UA_ByteString *)input[4].data;
    UA_ByteString *csr = UA_ByteString_new();

    retval = UA_Server_createSigningRequest(server, certificateGroupId,
                                            certificateTypeId, subjectName,
                                            regenerateKey, nonce, csr);

    if (retval != UA_STATUSCODE_GOOD) {
        return retval;
    }

    /* Output arg, the PKCS #10 DER encoded Certificate Request (CSR) */
    UA_Variant_setScalarCopy(output, csr, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_ByteString_delete(csr);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
getRejectedList(UA_Server *server,
                const UA_NodeId *sessionId, void *sessionHandle,
                const UA_NodeId *methodId, void *methodContext,
                const UA_NodeId *objectId, void *objectContext,
                size_t inputSize, const UA_Variant *input,
                size_t outputSize, UA_Variant *output) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    size_t rejectedListSize = 0;
    UA_CertificateGroup certGroup = server->config.secureChannelPKI;

    /* Default Application Group */
    UA_ByteString *rejectedListSecureChannel = NULL;
    size_t rejectedListSecureChannelSize = 0;
    certGroup.getRejectedList(&certGroup, &rejectedListSecureChannel, &rejectedListSecureChannelSize);
    rejectedListSize += rejectedListSecureChannelSize;

    /* User Token Group */
    certGroup = server->config.sessionPKI;
    UA_ByteString *rejectedListSession = NULL;
    size_t rejectedListSessionSize = 0;
    certGroup.getRejectedList(&certGroup, &rejectedListSession, &rejectedListSessionSize);
    rejectedListSize += rejectedListSessionSize;

    if(rejectedListSize == 0) {
        UA_Variant_setArray(&output[0], NULL, rejectedListSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        return UA_STATUSCODE_GOOD;
    }

    UA_ByteString *rejectedList = (UA_ByteString*)UA_Array_new(rejectedListSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    if(rejectedList == NULL) {
        UA_Array_delete(rejectedListSecureChannel, rejectedListSecureChannelSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        UA_Array_delete(rejectedListSession, rejectedListSessionSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    memcpy(rejectedList, rejectedListSecureChannel, rejectedListSecureChannelSize * sizeof(UA_ByteString));
    memcpy(rejectedList + rejectedListSecureChannelSize, rejectedListSession, rejectedListSessionSize * sizeof(UA_ByteString));

    UA_Variant_setArrayCopy(&output[0], rejectedList,
                        rejectedListSize, &UA_TYPES[UA_TYPES_BYTESTRING]);

    UA_Array_delete(rejectedListSecureChannel, rejectedListSecureChannelSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_Array_delete(rejectedListSession, rejectedListSessionSize, &UA_TYPES[UA_TYPES_BYTESTRING]);
    UA_free(rejectedList);

    return retval;
}

static UA_StatusCode
applyChanges(UA_Server *server,
             const UA_NodeId *sessionId, void *sessionHandle,
             const UA_NodeId *methodId, void *methodContext,
             const UA_NodeId *objectId, void *objectContext,
             size_t inputSize, const UA_Variant *input,
             size_t outputSize, UA_Variant *output) {
    return UA_STATUSCODE_BADNOTIMPLEMENTED;
}

static UA_StatusCode
writeGroupVariables(UA_Server *server) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* The server currently only supports the DefaultApplicationGroup */
    UA_CertificateGroup certGroup = server->config.secureChannelPKI;

    UA_NodeId defaultApplicationGroup = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    if(!UA_NodeId_equal(&certGroup.certificateGroupId, &defaultApplicationGroup))
        return UA_STATUSCODE_BADINTERNALERROR;

    /* TODO: Get CertifcateTypes from corresponding group */
    UA_NodeId certificateTypes[2] = {UA_NODEID_NUMERIC(0, UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE),
                                     UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE)};
    size_t certificateTypesSize = 2;

    UA_String supportedPrivateKeyFormats[2] = {UA_STRING("PEM"),
                                               UA_STRING("PFX")};
    size_t supportedPrivateKeyFormatsSize = 2;

    UA_UInt32  maxTrustListSize = 0;

    /* Set variables */
    retval |= writeGDSNs0VariableArray(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_SUPPORTEDPRIVATEKEYFORMATS),
                                       supportedPrivateKeyFormats, supportedPrivateKeyFormatsSize,
                                       &UA_TYPES[UA_TYPES_STRING]);

    retval |= writeGDSNs0Variable(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_MAXTRUSTLISTSIZE),
                                  &maxTrustListSize, &UA_TYPES[UA_TYPES_UINT32]);

    retval |= writeGDSNs0VariableArray(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP_CERTIFICATETYPES),
                                       certificateTypes, certificateTypesSize,
                                       &UA_TYPES[UA_TYPES_NODEID]);

    return retval;
}

UA_StatusCode
initNS0PushManagement(UA_Server *server) {
    UA_LOCK_ASSERT(&server->serviceMutex, 1);

    UA_StatusCode retval = UA_STATUSCODE_GOOD;

    /* Set variables */
    retval |= writeGroupVariables(server);

    /* Set method callbacks */
    retval |= setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_UPDATECERTIFICATE), updateCertificate);
    retval |= setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATIONTYPE_UPDATECERTIFICATE), updateCertificate);

    retval |= setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CREATESIGNINGREQUEST), createSigningRequest);
    retval |= setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATIONTYPE_CREATESIGNINGREQUEST), createSigningRequest);

    retval |= setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_GETREJECTEDLIST), getRejectedList);
    retval |= setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATIONTYPE_GETREJECTEDLIST), getRejectedList);

    retval |= setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_APPLYCHANGES), applyChanges);
    retval |= setMethodNode_callback(server, UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATIONTYPE_APPLYCHANGES), applyChanges);

    return retval;
}

#endif

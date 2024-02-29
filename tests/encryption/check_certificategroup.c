/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2024 (c) Fraunhofer IOSB (Author: Noel Graf)
 *
 */

#include <open62541/client.h>
#include <open62541/client_config_default.h>
#include <open62541/plugin/certificategroup_default.h>
#include <open62541/server.h>
#include <open62541/server_config_default.h>

#include "client/ua_client_internal.h"
#include "ua_server_internal.h"

#include <stdio.h>
#include <stdlib.h>

#include "test_helpers.h"
#include "certificates.h"
#include "check.h"
#include "thread_wrapper.h"

UA_Server *server;
UA_Boolean running;
THREAD_HANDLE server_thread;

THREAD_CALLBACK(serverloop) {
        while(running)
        UA_Server_run_iterate(server, true);
        return 0;
}

static void setup(void) {
    running = true;

    /* Load certificate and private key */
    UA_ByteString certificate;
    certificate.length = CERT_DER_LENGTH;
    certificate.data = CERT_DER_DATA;

    UA_ByteString privateKey;
    privateKey.length = KEY_DER_LENGTH;
    privateKey.data = KEY_DER_DATA;

    server = UA_Server_newForUnitTest();
    ck_assert(server != NULL);
    UA_ServerConfig *config = UA_Server_getConfig(server);
    UA_ServerConfig_setDefaultWithSecurityPolicies(config, 4840, &certificate, &privateKey,
                                                   NULL, 0,
                                                   NULL, 0,
                                                   NULL, 0);

    /* Set the ApplicationUri used in the certificate */
    UA_String_clear(&config->applicationDescription.applicationUri);
    config->applicationDescription.applicationUri =
            UA_STRING_ALLOC("urn:unconfigured:application");

    UA_Server_run_startup(server);
    THREAD_CREATE(server_thread, serverloop);
}

static void teardown(void) {
    running = false;
    THREAD_JOIN(server_thread);
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
}

START_TEST(set_trustlist) {

    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* Load certificate and private key */
    UA_ByteString trustedCertificate;
    trustedCertificate.length = CERT_DER_LENGTH;
    trustedCertificate.data = CERT_DER_DATA;

    UA_ByteString issuerCertificate;
    issuerCertificate.length = CERT_PEM_LENGTH;
    issuerCertificate.data = CERT_PEM_DATA;

    /* Add the specified list to the default application group */
    UA_TrustListDataType trustListTmp;
    memset(&trustListTmp, 0, sizeof(UA_TrustListDataType));

    trustListTmp.specifiedLists = (UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES | UA_TRUSTLISTMASKS_ISSUERCERTIFICATES);
    trustListTmp.trustedCertificates = &trustedCertificate;
    trustListTmp.trustedCertificatesSize = 1;
    trustListTmp.issuerCertificates = &issuerCertificate;
    trustListTmp.issuerCertificatesSize = 1;

    UA_StatusCode retval = config->secureChannelPKI.setTrustList(&config->secureChannelPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    retval = config->sessionPKI.setTrustList(&config->sessionPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
}
END_TEST

START_TEST(add_to_trustlist) {

    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* Load certificate and private key */
    UA_ByteString trustedCertificate;
    trustedCertificate.length = CERT_DER_LENGTH;
    trustedCertificate.data = CERT_DER_DATA;

    UA_ByteString issuerCertificate;
    issuerCertificate.length = CERT_PEM_LENGTH;
    issuerCertificate.data = CERT_PEM_DATA;

    /* Add the specified list to the default application group */
    UA_TrustListDataType trustListTmp;
    memset(&trustListTmp, 0, sizeof(UA_TrustListDataType));

    trustListTmp.specifiedLists = (UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES | UA_TRUSTLISTMASKS_ISSUERCERTIFICATES);
    trustListTmp.trustedCertificates = &trustedCertificate;
    trustListTmp.trustedCertificatesSize = 1;
    trustListTmp.issuerCertificates = &issuerCertificate;
    trustListTmp.issuerCertificatesSize = 1;

    UA_StatusCode retval = config->secureChannelPKI.addToTrustList(&config->secureChannelPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    retval = config->sessionPKI.addToTrustList(&config->sessionPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
}
END_TEST

START_TEST(get_trustlist) {

    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* Load certificate and private key */
    UA_ByteString trustedCertificate;
    trustedCertificate.length = CERT_DER_LENGTH;
    trustedCertificate.data = CERT_DER_DATA;

    UA_ByteString issuerCertificate;
    issuerCertificate.length = CERT_PEM_LENGTH;
    issuerCertificate.data = CERT_PEM_DATA;

    /* Add the specified list to the default application group */
    UA_TrustListDataType trustListTmp;
    memset(&trustListTmp, 0, sizeof(UA_TrustListDataType));

    trustListTmp.specifiedLists = (UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES | UA_TRUSTLISTMASKS_ISSUERCERTIFICATES);
    trustListTmp.trustedCertificates = &trustedCertificate;
    trustListTmp.trustedCertificatesSize = 1;
    trustListTmp.issuerCertificates = &issuerCertificate;
    trustListTmp.issuerCertificatesSize = 1;

    UA_StatusCode retval = config->secureChannelPKI.addToTrustList(&config->secureChannelPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    retval = config->sessionPKI.addToTrustList(&config->sessionPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    UA_TrustListDataType trustList;
    UA_TrustListDataType_init(&trustList);
    trustList.specifiedLists = UA_TRUSTLISTMASKS_ALL;

    retval = config->secureChannelPKI.getTrustList(&config->secureChannelPKI, &trustList);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert_uint_eq(trustList.trustedCertificatesSize, 1);
    ck_assert_uint_eq(trustList.issuerCertificatesSize, 1);
    ck_assert_uint_eq(trustList.trustedCrlsSize, 0);
    ck_assert_uint_eq(trustList.issuerCrlsSize, 0);

    ck_assert(UA_ByteString_equal(&trustedCertificate, &trustList.trustedCertificates[0]));
    ck_assert(UA_ByteString_equal(&issuerCertificate, &trustList.issuerCertificates[0]));

    UA_TrustListDataType_clear(&trustList);
}
END_TEST

START_TEST(remove_from_trustlist) {

    UA_ServerConfig *config = UA_Server_getConfig(server);

    /* Load certificate and private key */
    UA_ByteString trustedCertificate;
    trustedCertificate.length = CERT_DER_LENGTH;
    trustedCertificate.data = CERT_DER_DATA;

    UA_ByteString issuerCertificate;
    issuerCertificate.length = CERT_PEM_LENGTH;
    issuerCertificate.data = CERT_PEM_DATA;

    /* Add the specified list to the default application group */
    UA_TrustListDataType trustListTmp;
    memset(&trustListTmp, 0, sizeof(UA_TrustListDataType));

    trustListTmp.specifiedLists = (UA_TRUSTLISTMASKS_TRUSTEDCERTIFICATES | UA_TRUSTLISTMASKS_ISSUERCERTIFICATES);
    trustListTmp.trustedCertificates = &trustedCertificate;
    trustListTmp.trustedCertificatesSize = 1;
    trustListTmp.issuerCertificates = &issuerCertificate;
    trustListTmp.issuerCertificatesSize = 1;

    UA_StatusCode retval = config->secureChannelPKI.setTrustList(&config->secureChannelPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    retval = config->sessionPKI.setTrustList(&config->sessionPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    retval = config->secureChannelPKI.removeFromTrustList(&config->secureChannelPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    retval = config->sessionPKI.removeFromTrustList(&config->sessionPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
}
END_TEST

START_TEST(get_rejectedlist) {
    /* Init client and connect to server */
    UA_Client *client = NULL;
    UA_ByteString *trustList = NULL;
    size_t trustListSize = 0;
    UA_ByteString *revocationList = NULL;
    size_t revocationListSize = 0;

    /* Load certificate and private key */
    UA_ByteString certificate;
    certificate.length = CERT_DER_LENGTH;
    certificate.data = CERT_DER_DATA;
    ck_assert_uint_ne(certificate.length, 0);

    UA_ByteString privateKey;
    privateKey.length = KEY_DER_LENGTH;
    privateKey.data = KEY_DER_DATA;
    ck_assert_uint_ne(privateKey.length, 0);

    /* Secure client initialization */
    client = UA_Client_newForUnitTest();
    UA_ClientConfig *cc = UA_Client_getConfig(client);
    UA_ClientConfig_setDefaultEncryption(cc, certificate, privateKey,
                                         trustList, trustListSize,
                                         revocationList, revocationListSize);
    cc->certificateVerification.clear(&cc->certificateVerification);
    UA_CertificateGroup_AcceptAll(&cc->certificateVerification);
    cc->securityPolicyUri =
            UA_STRING_ALLOC("http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256");
    ck_assert(client != NULL);

    /* Set server config */
    UA_ServerConfig *config = UA_Server_getConfig(server);
    /* Load certificate and private key */
    UA_ByteString issuerCertificate;
    issuerCertificate.length = CERT_DER_LENGTH;
    issuerCertificate.data = CERT_DER_DATA;

    /* Add the specified list to the default application group */
    UA_TrustListDataType trustListTmp;
    memset(&trustListTmp, 0, sizeof(UA_TrustListDataType));

    trustListTmp.specifiedLists = UA_TRUSTLISTMASKS_ISSUERCERTIFICATES;
    trustListTmp.issuerCertificates = &issuerCertificate;
    trustListTmp.issuerCertificatesSize = 1;

    UA_StatusCode retval = config->secureChannelPKI.setTrustList(&config->secureChannelPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    retval = config->sessionPKI.setTrustList(&config->sessionPKI, &trustListTmp);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    /* Secure client connect */
    retval = UA_Client_connect(client, "opc.tcp://localhost:4840");
    ck_assert_uint_eq(retval, UA_STATUSCODE_BADSECURITYCHECKSFAILED);

    UA_Client_delete(client);
}
END_TEST

START_TEST(update_server_certificate) {
    /* Load certificate and private key */
    UA_ByteString certificate;
    certificate.length = CERT_DER_LENGTH;
    certificate.data = CERT_DER_DATA;

    UA_ByteString privateKey;
    privateKey.length = KEY_DER_LENGTH;
    privateKey.data = KEY_DER_DATA;

    UA_NodeId groupId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId typeId = UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_StatusCode retval =
            UA_Server_updateCertificate(server, &groupId, &typeId, &certificate, NULL, 0, &privateKey, NULL);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);

    typeId = UA_NODEID_NUMERIC(0, UA_NS0ID_RSAMINAPPLICATIONCERTIFICATETYPE);
    retval =
            UA_Server_updateCertificate(server, &groupId, &typeId, &certificate, NULL, 0, &privateKey, NULL);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
}
END_TEST

START_TEST(create_signing_request) {
    UA_ByteString *csr = UA_ByteString_new();
    UA_NodeId groupId = UA_NODEID_NUMERIC(0, UA_NS0ID_SERVERCONFIGURATION_CERTIFICATEGROUPS_DEFAULTAPPLICATIONGROUP);
    UA_NodeId typeId = UA_NODEID_NUMERIC(0, UA_NS0ID_RSASHA256APPLICATIONCERTIFICATETYPE);
    UA_StatusCode retval =
            UA_Server_createSigningRequest(server, &groupId, &typeId, NULL, NULL, NULL, csr);
    ck_assert_uint_eq(retval, UA_STATUSCODE_GOOD);
    ck_assert_uint_ne(csr->length, 0);

    UA_ByteString_delete(csr);
}
END_TEST


static Suite* testSuite_encryption(void) {
    Suite *s = suite_create("CertificateGroup");
    TCase *tc_encryption = tcase_create("CertificateGroup");
    tcase_add_checked_fixture(tc_encryption, setup, teardown);
#ifdef UA_ENABLE_ENCRYPTION
    tcase_add_test(tc_encryption, set_trustlist);
    tcase_add_test(tc_encryption, get_trustlist);
    tcase_add_test(tc_encryption, add_to_trustlist);
    tcase_add_test(tc_encryption, remove_from_trustlist);
    tcase_add_test(tc_encryption, get_rejectedlist);
    tcase_add_test(tc_encryption, update_server_certificate);
    tcase_add_test(tc_encryption, create_signing_request);
#endif /* UA_ENABLE_ENCRYPTION */
    suite_add_tcase(s,tc_encryption);
    return s;
}

int main(void) {
    Suite *s = testSuite_encryption();
    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all(sr,CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

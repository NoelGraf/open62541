#include "common.h"

#ifdef UA_ENABLE_ENCRYPTION
#include <open62541/plugin/create_certificate.h>
#include <open62541/plugin/pki_default.h>
#endif

#include <open62541/client_config_default.h>
#include <open62541/plugin/log_stdout.h>

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

UA_Boolean running = true;

static void stopHandler(int sign) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_CLIENT, "Received Ctrl-C");
    running = 0;
}

static void alarm_handler(int sign) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_CLIENT, "The program has reached the specified time and is now exiting.");
    running = 0;
}

static void usage(void) {
    printf("Usage: client_profile_1 -n value -s value -m value\n"
            "-n, --nodes\t\t\tNumber of nodes to be read via a repeated callback.\n"
            "-s, --numberOfSubs\t\tNumber of subscriptions to create.\n"
            "-m, --monitoredItemsPerSubs\tNumber of MonitoredItems to be created per subscription.\n"
            "-t, --time\t\t\tAmount of seconds to keep the client running."
#ifdef UA_ENABLE_ENCRYPTION
           "--encryption\t\t\tUse encryption if specified.\n"
           "--cert\t\t\tPath to the server certificate.\n"
           "--key\t\t\tPath to the server PrivateKey.\n"
           "--securityMode\t\t\tNone[1], Sign[2], Sign&Encrypt[3].\n"
           "--securityPolicy\t\tPolicy used for the connection.\n");
#else
    );
#endif
}

int main(int argc, char *argv[]) {
    // Register the SIGINT handler
    signal(SIGINT, stopHandler); /* catches ctrl-c */

    // Register the SIGALRM handler
    signal(SIGALRM, alarm_handler);

    int nodes;
    int numberOfSubs;
    int monitoredItemsPerSubs;
    int time;
#ifdef UA_ENABLE_ENCRYPTION
    bool enableEncryption = false;
    char *certfile = NULL;
    char *keyfile = NULL;
    volatile UA_String securityPolicyUri = UA_STRING_NULL;
    UA_MessageSecurityMode securityMode = UA_MESSAGESECURITYMODE_INVALID;
#endif

    if(argc <= 1) {
        usage();
        return EXIT_SUCCESS;
    }

    /* Parse the arguments */
    for(int argpos = 1; argpos < argc; argpos++) {
        if(strcmp(argv[argpos], "--help") == 0 ||
           strcmp(argv[argpos], "-h") == 0) {
            usage();
            return EXIT_SUCCESS;
        }

        if(strcmp(argv[argpos], "--nodes") == 0 ||
           strcmp(argv[argpos], "-n") == 0) {
            argpos++;
            if(sscanf(argv[argpos], "%i", (int*)&nodes) != 1) {
                return EXIT_FAILURE;
            }
            continue;
        }

        if(strcmp(argv[argpos], "--numberOfSubs") == 0 ||
           strcmp(argv[argpos], "-s") == 0) {
            argpos++;
            if(sscanf(argv[argpos], "%i", (int*)&numberOfSubs) != 1) {
                return EXIT_FAILURE;
            }
            continue;
        }

        if(strcmp(argv[argpos], "--monitoredItemsPerSubs") == 0 ||
           strcmp(argv[argpos], "-m") == 0) {
            argpos++;
            if(sscanf(argv[argpos], "%i", (int*)&monitoredItemsPerSubs) != 1) {
                return EXIT_FAILURE;
            }
            continue;
        }

        if(strcmp(argv[argpos], "--time") == 0 ||
           strcmp(argv[argpos], "-t") == 0) {
            argpos++;
            if(sscanf(argv[argpos], "%i", (int*)&time) != 1) {
                return EXIT_FAILURE;
            }
            continue;
        }

#ifdef UA_ENABLE_ENCRYPTION
        if(strcmp(argv[argpos], "--encryption") == 0) {
            argpos++;
            enableEncryption = true;
            continue;
        }

        if(strcmp(argv[argpos], "--cert") == 0) {
            argpos++;
            certfile = argv[argpos];
            enableEncryption = true;
            continue;
        }

        if(strcmp(argv[argpos], "--key") == 0) {
            argpos++;
            keyfile = argv[argpos];
            enableEncryption = true;
            continue;
        }

        if(strcmp(argv[argpos], "--securityMode") == 0) {
            argpos++;
            if(sscanf(argv[argpos], "%i", (int*)&securityMode) != 1) {
                usage();
                return 0;
            }
            enableEncryption = true;
            continue;
        }

        if(strcmp(argv[argpos], "--securityPolicy") == 0) {
            argpos++;
            securityPolicyUri = UA_String_fromChars(argv[argpos]);
            enableEncryption = true;
            continue;
        }
#endif

        usage();
        return EXIT_SUCCESS;
    }

    UA_Client *client = UA_Client_new();
    UA_ClientConfig *cc = UA_Client_getConfig(client);

    /* Set stateCallback */
    cc->subscriptionInactivityCallback = subscriptionInactivityCallback;

#ifdef UA_ENABLE_ENCRYPTION
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    if(enableEncryption) {
        /* Set securityMode and securityPolicyUri */
        cc->securityMode = securityMode;
        cc->securityPolicyUri = securityPolicyUri;

        /* Accept all certificates */
        UA_CertificateVerification_AcceptAll(&cc->certificateVerification);

        if(certfile && keyfile) {
            certificate = loadFile(certfile);
            privateKey  = loadFile(keyfile);
        } else {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Missing arguments. Arguments are "
                         "<client-certificate.der> <private-key.der> ");
#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) || defined(UA_ENABLE_ENCRYPTION_LIBRESSL)
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Trying to create a certificate.");
            UA_String subject[3] = {UA_STRING_STATIC("C=DE"),
                                    UA_STRING_STATIC("O=SampleOrganization"),
                                    UA_STRING_STATIC("CN=Open62541Client@localhost")};
            UA_UInt32 lenSubject = 3;
            UA_String subjectAltName[2] = {
                UA_STRING_STATIC("DNS:desktop-210i928"), //localhost
                UA_STRING_STATIC("URI:urn:open62541.client.application")
            };
            UA_UInt32 lenSubjectAltName = 2;
            UA_KeyValueMap *kvm = UA_KeyValueMap_new();
            UA_UInt16 expiresIn = 14;
            UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "expires-in-days"),
                                     (void *) &expiresIn, &UA_TYPES[UA_TYPES_UINT16]);
            UA_StatusCode statusCertGen = UA_CreateCertificate(
                UA_Log_Stdout, subject, lenSubject, subjectAltName, lenSubjectAltName,
                UA_CERTIFICATEFORMAT_DER, kvm, &privateKey, &certificate);
            UA_KeyValueMap_delete(kvm);

            if (statusCertGen != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                            "Generating Certificate failed: %s",
                            UA_StatusCode_name(statusCertGen));
                return EXIT_FAILURE;
            }
#else
            return EXIT_FAILURE;
#endif
        }
    }
#endif

#ifdef UA_ENABLE_ENCRYPTION
    if(enableEncryption) {
        /* The application URI must be the same as the one in the certificate.
         * The script for creating a self-created certificate generates a certificate
         * with the Uri specified below.*/
        UA_ApplicationDescription_clear(&cc->clientDescription);
        cc->clientDescription.applicationUri = UA_STRING_ALLOC("urn:open62541.client.application");
        cc->clientDescription.applicationType = UA_APPLICATIONTYPE_CLIENT;

        UA_ClientConfig_setDefaultEncryption(cc, certificate, privateKey,
                                             NULL, 0, NULL, 0);
        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
    }else {
        UA_ClientConfig_setDefault(cc);
    }
#else
    UA_ClientConfig_setDefault(cc);
#endif

    /* Connect */
    UA_StatusCode retval = UA_Client_connect(client, "opc.tcp://localhost:4840");
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Could not connect.");
        UA_Client_delete(client);
        return EXIT_SUCCESS;
    }
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Connected!");

    /* Read numberOfNodes and nodesPerLevel */
    UA_UInt32 numberOfNodes = 0;
    UA_UInt32 nodesPerLevel = 0;
    readNodesetInformation(client, &numberOfNodes, &nodesPerLevel);

    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Number of Nodes: %i", numberOfNodes);
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Number per Level: %i", nodesPerLevel);

    if(nodes > (int)numberOfNodes || (numberOfSubs * monitoredItemsPerSubs) > (int)numberOfNodes) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Too few nodes present in the information model.");
        return EXIT_FAILURE;
    }

    UA_NodeInfo *info = UA_NodeInfo_new();
    info->nodesPerLevel = (int)nodesPerLevel;
    info->numberOfNodes = (int)numberOfNodes;
    info->nodes = nodes;
    info->numberOfSubscriptions = numberOfSubs;
    info->monitoredItemsPerSubscriptions = monitoredItemsPerSubs;

    /* Create repeated Callbacks */
    createRepeatedCallbacks(client, info, 5000.0);

    /* Create Subscriptions with MonitoredItems */
    createSubscriptionsWithMonitoredItems(client, info);

    /* Start alarm timer */
    alarm(time);

    /* For debugging purpose(valgrind) */
//    for(int i = 0; i < 6000; i++) {
//        UA_Client_run_iterate(client, 100);
//    }
    while(running) {
        UA_Client_run_iterate(client, 100);
    }

    /* Delete Repeated Callbacks */
    deleteRepeatedCallbacks(client, info);

    /* Delete Subscriptions and MonitoredItems*/
    deleteSubscriptionsWithMonitoredItems(client, info);

    /* Clean up */
    UA_NodeInfo_delete(info);
    UA_Client_disconnect(client);
    UA_Client_delete(client);
    return EXIT_SUCCESS;
}

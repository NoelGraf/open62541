#include "common.h"
#ifdef UA_ENABLE_ENCRYPTION
#include <open62541/server_config_default.h>
#include <open62541/plugin/create_certificate.h>
#endif

#include <open62541/server.h>
#include <open62541/plugin/log_stdout.h>

#include <stdio.h>
#include <signal.h>

UA_Boolean running = true;
UA_Boolean wasConnected = false;
UA_Boolean alarmIsSet = false;

static void stopHandler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "received ctrl-c");
    running = false;
}

static void alarm_handler(int sig) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_CLIENT, "The program has reached the specified time and is now exiting.");
    running = false;
}

static void
dummyCallback(UA_Server *server, void *data) {
    size_t sessionCount = UA_Server_getStatistics(server).ss.currentSessionCount;
    if(sessionCount > 0) {
        wasConnected = true;
        if(alarmIsSet) {
            alarm(0);
            alarmIsSet = false;
        }
    } else {
        if(wasConnected && !alarmIsSet) {
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Last client disconnected.");
            int timeout = *(int*)data;
            alarm(timeout);
            alarmIsSet = true;
        }
    }
}

static void usage(void) {
    printf("Usage: server_profile_1 -n value -l value\n"
           "-n, --numberOfNodes\tNumber of nodes to create.\n"
           "-l, --nodesPerLevel\tNumber of nodes to be created on a level.\n"
           "-t, --timeout\t\tNumber of seconds to keep the server running after the last client disconnects.\n"
#ifdef UA_ENABLE_ENCRYPTION
           "--encryption\t\t\tUse encryption if specified.\n"
           "--cert\t\t\tPath to the server certificate.\n"
           "--key\t\t\tPath to the server PrivateKey.\n");
#else
    );
#endif
}

int main(int argc, char *argv[]) {
    signal(SIGINT, stopHandler);
    signal(SIGALRM, alarm_handler);

    int numberOfNodes;
    int nodesPerLevel;
    int timeout;
#ifdef UA_ENABLE_ENCRYPTION
    bool enableEncryption = false;
    char *certfile = NULL;
    char *keyfile = NULL;
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

        if(strcmp(argv[argpos], "--numberOfNodes") == 0 ||
           strcmp(argv[argpos], "-n") == 0) {
            argpos++;
            if(sscanf(argv[argpos], "%i", (int*)&numberOfNodes) != 1) {
                return EXIT_FAILURE;
            }
            continue;
        }

        if(strcmp(argv[argpos], "--nodesPerLevel") == 0 ||
           strcmp(argv[argpos], "-l") == 0) {
            argpos++;
            if(sscanf(argv[argpos], "%i", (int*)&nodesPerLevel) != 1) {
                return EXIT_FAILURE;
            }
            continue;
        }

        if(strcmp(argv[argpos], "--timeout") == 0 ||
           strcmp(argv[argpos], "-t") == 0) {
            argpos++;
            if(sscanf(argv[argpos], "%i", (int*)&timeout) != 1) {
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
#endif

        usage();
        return EXIT_SUCCESS;
    }

#ifdef UA_ENABLE_ENCRYPTION
    UA_ByteString certificate = UA_BYTESTRING_NULL;
    UA_ByteString privateKey = UA_BYTESTRING_NULL;
    if(enableEncryption) {
        if(certfile && keyfile) {
            /* Load certificate and private key */
            certificate = loadFile(certfile);
            privateKey = loadFile(keyfile);
        } else {
            UA_LOG_FATAL(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                         "Missing arguments. Arguments are "
                         "<server-certificate.der> <private-key.der> ");
#if defined(UA_ENABLE_ENCRYPTION_OPENSSL) || defined(UA_ENABLE_ENCRYPTION_LIBRESSL)
            UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                        "Trying to create a certificate.");
            UA_String subject[3] = {UA_STRING_STATIC("C=DE"),
                                    UA_STRING_STATIC("O=SampleOrganization"),
                                    UA_STRING_STATIC("CN=Open62541Server@localhost")};
            UA_UInt32 lenSubject = 3;
            UA_String subjectAltName[2] = {
                UA_STRING_STATIC("DNS:desktop-210i928"), //localhost
                UA_STRING_STATIC("URI:urn:open62541.server.application")
            };
            UA_UInt32 lenSubjectAltName = 2;
            UA_KeyValueMap *kvm = UA_KeyValueMap_new();
            UA_UInt16 expiresIn = 14;
            UA_KeyValueMap_setScalar(kvm, UA_QUALIFIEDNAME(0, "expires-in-days"),
                                     (void *)&expiresIn, &UA_TYPES[UA_TYPES_UINT16]);
            UA_StatusCode statusCertGen = UA_CreateCertificate(
                UA_Log_Stdout, subject, lenSubject, subjectAltName, lenSubjectAltName,
                UA_CERTIFICATEFORMAT_DER, kvm, &privateKey, &certificate);
            UA_KeyValueMap_delete(kvm);

            if(statusCertGen != UA_STATUSCODE_GOOD) {
                UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                            "Generating Certificate failed: %s",
                            UA_StatusCode_name(statusCertGen));
                return EXIT_FAILURE;
            }
        }
    }
#else
        return EXIT_FAILURE;
#endif
#endif

    UA_Server *server = UA_Server_new();
    UA_ServerConfig *config = UA_Server_getConfig(server);

#ifdef UA_ENABLE_ENCRYPTION
    if(enableEncryption) {
        UA_ServerConfig_setDefaultWithSecurityPolicies(config, 4840,
                                                       &certificate, &privateKey,
                                                       NULL, 0, NULL, 0, NULL, 0);
        UA_ByteString_clear(&certificate);
        UA_ByteString_clear(&privateKey);
    }
#endif

    generate_testnodeset(server, numberOfNodes, nodesPerLevel);

    UA_UInt64 id;
    UA_Server_addRepeatedCallback(server, dummyCallback, &timeout, 1000, &id);

    UA_Server_run_startup(server);
    while(running) {
        UA_Server_run_iterate(server, false);
    }

//    UA_Server_runUntilInterrupt(server);
    UA_Server_removeCallback(server, id);
    UA_Server_run_shutdown(server);
    UA_Server_delete(server);
    return 0;
}

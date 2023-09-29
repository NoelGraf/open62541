#include <open62541/server.h>

struct UA_NodeInfo;
typedef struct UA_NodeInfo UA_NodeInfo;

struct UA_SubMonInfo;
typedef struct UA_SubMonInfo UA_SubMonInfo;

struct UA_NodeInfo {
    int nodesPerLevel;
    int numberOfNodes;
    int nodes;
    int numberOfSubscriptions;
    int monitoredItemsPerSubscriptions;
    UA_UInt32 *nodeIds; /* List to hold the created node IDs */
    UA_UInt64 *callbackIds; /* List to hold the created callback IDs */
    UA_SubMonInfo *subMonInfo; /* List to hold the created subscription IDs and the corresponding monitoredItemIds*/
};

struct UA_SubMonInfo {
    UA_UInt32 subId;
    UA_UInt32 *monIds;
    UA_UInt32 *nodeIds;
};

/********************************/
/* Default UA_NodeInfo Settings */
/********************************/

UA_NodeInfo *
UA_NodeInfo_new(void);

void
UA_NodeInfo_delete(UA_NodeInfo *info);

UA_ByteString
loadFile(const char *const path);

UA_StatusCode
generate_testnodeset(UA_Server *server, int numOfNodes, int level);

void
createRepeatedCallbacks(UA_Client *client, UA_NodeInfo *info, UA_Double interval_ms);

void
deleteRepeatedCallbacks(UA_Client *client, UA_NodeInfo *info);

void
createSubscriptionsWithMonitoredItems(UA_Client *client, UA_NodeInfo *info);

void
deleteSubscriptionsWithMonitoredItems(UA_Client *client, UA_NodeInfo *info);

void
subscriptionInactivityCallback(UA_Client *client, UA_UInt32 subId, void *subContext);

void
readNodesetInformation(UA_Client *client, UA_UInt32 *numberOfNodes, UA_UInt32 *nodesPerLevel);

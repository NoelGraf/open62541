#include "common.h"

#include <open62541/plugin/log_stdout.h>
#include <open62541/client_subscriptions.h>
#include <open62541/client_highlevel.h>
#include <open62541/client_highlevel_async.h>

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

static UA_StatusCode
addInputNodes(UA_Server *server, int numOfNodes, int nodesPerLevel);
static UA_StatusCode
generate_objectWithNodes(UA_Server *server, int remainingNodes, int nodesPerLevel, const UA_NodeId parentNodeId, int id);

UA_StatusCode
generate_testnodeset(UA_Server *server, int numOfNodes, int nodesPerLevel) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    retval = addInputNodes(server, numOfNodes, nodesPerLevel);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "function addInputNodes failed.");
        return retval;
    }
    retval = generate_objectWithNodes(server, numOfNodes, nodesPerLevel, UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER), 2000);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_SERVER, "function generate_objectWithNodes failed.");
    }
    return retval;
}

static void
beforeReadTime(UA_Server *server,
               const UA_NodeId *sessionId, void *sessionContext,
               const UA_NodeId *nodeid, void *nodeContext,
               const UA_NumericRange *range, const UA_DataValue *data) {
    UA_UInt32 newValue = rand();
    UA_Variant value;
    UA_Variant_setScalar(&value, &newValue, &UA_TYPES[UA_TYPES_UINT32]);
    UA_Server_writeValue(server, *nodeid, value);
}

static void
afterWriteTime(UA_Server *server,
               const UA_NodeId *sessionId, void *sessionContext,
               const UA_NodeId *nodeId, void *nodeContext,
               const UA_NumericRange *range, const UA_DataValue *data) {
}

static void
addValueCallbackToCurrentTimeVariable(UA_Server *server, const UA_NodeId nodeId) {
    UA_ValueCallback callback ;
    callback.onRead = beforeReadTime;
    callback.onWrite = afterWriteTime;
    UA_Server_setVariableNode_valueCallback(server, nodeId, callback);
}

static UA_StatusCode
generate_objectWithNodes(UA_Server *server, int remainingNodes, int nodesPerLevel, const UA_NodeId parentNodeId, int id) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_NodeId objectId;
    UA_ObjectAttributes objectAttr = UA_ObjectAttributes_default;
    int ident = id/1000;
    char str[2] = {(char)65-2+ident, '\0'};
    objectAttr.displayName = UA_LOCALIZEDTEXT("en-US", str);
    retval |= UA_Server_addObjectNode(server, UA_NODEID_NUMERIC(1, id),
                            parentNodeId,
                            UA_NODEID_NUMERIC(0, UA_NS0ID_ORGANIZES),
                            UA_QUALIFIEDNAME(1, "A"),
                            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEOBJECTTYPE),
                            objectAttr, NULL, &objectId);
    int nodeToCreate = 0;
    if(remainingNodes >= nodesPerLevel)
        nodeToCreate = nodesPerLevel;
    else
        nodeToCreate = remainingNodes;

    for(int i = 0; i < nodeToCreate; i++) {
        UA_VariableAttributes variableAttr = UA_VariableAttributes_default;
        UA_UInt32 numOfNodesValue = rand();
        UA_Variant_setScalar(&variableAttr.value, &numOfNodesValue, &UA_TYPES[UA_TYPES_UINT32]);
        char str[2] = {(char)49+i, '\0'};
        variableAttr.displayName = UA_LOCALIZEDTEXT("en-EN", str);
        variableAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
        variableAttr.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
        UA_NodeId nodeId = UA_NODEID_NUMERIC(1,id + 1 + i);
        retval |= UA_Server_addVariableNode(server, nodeId, objectId,
                                            UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), UA_QUALIFIEDNAME(1, str),
                                            UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), variableAttr, NULL, NULL);
        addValueCallbackToCurrentTimeVariable(server, nodeId);
    }
    remainingNodes -= nodeToCreate;
    if(retval != UA_STATUSCODE_GOOD)
        return retval;
    if(remainingNodes > 0) {
        retval = generate_objectWithNodes(server, remainingNodes, nodesPerLevel, objectId, id + 1000);
        if(retval != UA_STATUSCODE_GOOD)
            return retval;
    }
    return retval;
}


static UA_StatusCode
addInputNodes(UA_Server *server, int numOfNodes, int nodesPerLevel) {
    UA_StatusCode retval = UA_STATUSCODE_GOOD;
    UA_VariableAttributes numOfNodesAttr = UA_VariableAttributes_default;
    UA_UInt32 numOfNodesValue = numOfNodes;
    UA_Variant_setScalar(&numOfNodesAttr.value, &numOfNodesValue, &UA_TYPES[UA_TYPES_UINT32]);
    numOfNodesAttr.displayName = UA_LOCALIZEDTEXT("en-EN", "Number of Nodes");
    numOfNodesAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    numOfNodesAttr.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    retval |= UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1,1000), UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), UA_QUALIFIEDNAME(1, "numOfNodes"),
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), numOfNodesAttr, NULL, NULL);

    UA_VariableAttributes levelAttr = UA_VariableAttributes_default;
    UA_UInt32 levelValue = nodesPerLevel;
    UA_Variant_setScalar(&levelAttr.value, &levelValue, &UA_TYPES[UA_TYPES_UINT32]);
    levelAttr.displayName = UA_LOCALIZEDTEXT("en-EN", "Nodes per Level");
    levelAttr.accessLevel = UA_ACCESSLEVELMASK_READ | UA_ACCESSLEVELMASK_WRITE;
    levelAttr.dataType = UA_TYPES[UA_TYPES_UINT32].typeId;
    retval |= UA_Server_addVariableNode(server, UA_NODEID_NUMERIC(1,1001), UA_NODEID_NUMERIC(0, UA_NS0ID_OBJECTSFOLDER),
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_HASCOMPONENT), UA_QUALIFIEDNAME(1, "level"),
                                      UA_NODEID_NUMERIC(0, UA_NS0ID_BASEDATAVARIABLETYPE), levelAttr, NULL, NULL);
    return retval;
}

static void
handler_nodeChanged(UA_Client *client, UA_UInt32 subId, void *subContext,
                    UA_UInt32 monId, void *monContext, UA_DataValue *value) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Node has changed!");
    if(UA_Variant_hasScalarType(&value->value, &UA_TYPES[UA_TYPES_UINT32])) {
        UA_UInt32 data = *(UA_UInt32*) value->value.data;
        UA_UInt32 *nodeId = (UA_UInt32*)monContext;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Value: %i", data);
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Value of node has changed (1, %i): %i", *nodeId, data);
    }
}

static void
deleteSubscriptionCallback(UA_Client *client, UA_UInt32 subscriptionId, void *subscriptionContext) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                "Subscription Id %u was deleted", subscriptionId);
}

void
createSubscriptionsWithMonitoredItems(UA_Client *client, UA_NodeInfo *info) {

    int remainingNodesInLevel = info->nodesPerLevel;
    int remainingNodes = info->numberOfNodes;
    int currentLevel = 0;
    info->subMonInfo = (UA_SubMonInfo*)UA_malloc(info->numberOfSubscriptions * sizeof(UA_SubMonInfo));

    /* Create Subscriptions */
    for(int i = 0; i < info->numberOfSubscriptions; i++) {
        /* Create a Subscription */
        UA_CreateSubscriptionRequest request = UA_CreateSubscriptionRequest_default();
        UA_CreateSubscriptionResponse response =
                UA_Client_Subscriptions_create(client, request, NULL, NULL, deleteSubscriptionCallback);
        if(response.responseHeader.serviceResult != UA_STATUSCODE_GOOD) {
            UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Could not create a Subscription with error %s",
                         UA_StatusCode_name(response.responseHeader.serviceResult));
        }
        info->subMonInfo[i].subId = response.subscriptionId;
        info->subMonInfo[i].monIds = (UA_UInt32*)UA_malloc(info->monitoredItemsPerSubscriptions * sizeof(UA_UInt32));
        info->subMonInfo[i].nodeIds = (UA_UInt32*)UA_malloc(info->monitoredItemsPerSubscriptions * sizeof(UA_UInt32));

        /* Add MonitoredItems */
        for(int j = 0; j < info->monitoredItemsPerSubscriptions; j++) {
            if(remainingNodesInLevel <= 0) {
                currentLevel += 1;
                if(remainingNodes >= info->nodesPerLevel)
                    remainingNodesInLevel = info->nodesPerLevel;
                else {
                    remainingNodesInLevel = remainingNodes;
                }
            }

            info->subMonInfo[i].nodeIds[j] = 2000 + (1000 * currentLevel) + remainingNodesInLevel;

            /* Add a MonitoredItem */
            UA_NodeId nodeId = UA_NODEID_NUMERIC(1, info->subMonInfo[i].nodeIds[j]);
            UA_MonitoredItemCreateRequest monRequest = UA_MonitoredItemCreateRequest_default(nodeId);
            UA_MonitoredItemCreateResult monResponse =
                    UA_Client_MonitoredItems_createDataChange(client, response.subscriptionId,
                                                              UA_TIMESTAMPSTORETURN_BOTH, monRequest,
                                                              &info->subMonInfo[i].nodeIds[j], handler_nodeChanged, NULL);
            if(monResponse.statusCode != UA_STATUSCODE_GOOD) {
                UA_LOG_ERROR(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                             "Could not create a MonitoredItem with error %s",
                             UA_StatusCode_name(response.responseHeader.serviceResult));
            }
            info->subMonInfo[i].monIds[j] = monResponse.monitoredItemId;
            remainingNodes -= 1;
            remainingNodesInLevel -= 1;
        }
    }
}

void
deleteSubscriptionsWithMonitoredItems(UA_Client *client, UA_NodeInfo *info) {
    for(int i = 0; i < info->numberOfSubscriptions; i++) {
        for(int j = 0; j < info->monitoredItemsPerSubscriptions; j++) {
            UA_Client_MonitoredItems_deleteSingle(client, info->subMonInfo[i].subId, info->subMonInfo[i].monIds[j]);
        }
        UA_Client_Subscriptions_deleteSingle(client, info->subMonInfo[i].subId);
    }
}

static void
readValueAttributeCallback(UA_Client *client, void *userdata,
                           UA_UInt32 requestId, UA_StatusCode status,
                           UA_DataValue *var) {
    if(UA_Variant_hasScalarType(&var->value, &UA_TYPES[UA_TYPES_UINT32])) {
        UA_Int32 int_val = *(UA_Int32*) var->value.data;
        UA_UInt32 *nodeId = (UA_UInt32*)userdata;
        UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND,
                    "Reading the value of node (1, %i): %i", *nodeId, int_val);
    }
}

static void
callReadAttributeCallback(UA_Client *client, void *id) {
    UA_UInt32 nodeId = *(UA_UInt32*)id;
    UA_Client_readValueAttribute_async(client, UA_NODEID_NUMERIC(1, nodeId), &readValueAttributeCallback, id, NULL);
}

void
createRepeatedCallbacks(UA_Client *client, UA_NodeInfo *info, UA_Double interval_ms) {
    int remainingNodesInLevel = info->nodesPerLevel;
    int remainingNodes = info->numberOfNodes;
    int currentLevel = 0;
    info->nodeIds = (UA_UInt32*)UA_malloc(info->nodes * sizeof(UA_UInt32));
    info->callbackIds = (UA_UInt64*)UA_malloc(info->nodes * sizeof(UA_UInt64));

    for(int i = 0; i < info->nodes; i++) {
        if(remainingNodesInLevel <= 0) {
            currentLevel += 1;
            if(remainingNodes >= info->nodesPerLevel)
                remainingNodesInLevel = info->nodesPerLevel;
            else {
                remainingNodesInLevel = remainingNodes;
            }
        }
        info->nodeIds[i] = 2000 + (1000 * currentLevel) + remainingNodesInLevel;
        UA_UInt64 timerCallbackId = 0;
        UA_Client_addRepeatedCallback(client, callReadAttributeCallback, &info->nodeIds[i], interval_ms, &timerCallbackId);
        info->callbackIds[i] = timerCallbackId;
        remainingNodes -= 1;
        remainingNodesInLevel -= 1;
    }
}

void
deleteRepeatedCallbacks(UA_Client *client, UA_NodeInfo *info) {
    for(int i = 0; i < info->nodes; i++) {
        UA_Client_removeCallback(client, info->callbackIds[i]);
    }
}

void
subscriptionInactivityCallback(UA_Client *client, UA_UInt32 subId, void *subContext) {
    UA_LOG_INFO(UA_Log_Stdout, UA_LOGCATEGORY_USERLAND, "Inactivity for subscription %u", subId);
}

void
readNodesetInformation(UA_Client *client, UA_UInt32 *numberOfNodes, UA_UInt32 *nodesPerLevel) {
    UA_Variant *value = UA_Variant_new();
    UA_Client_readValueAttribute(client, UA_NODEID_NUMERIC(1, 1000), value);
    if(UA_Variant_hasScalarType(value, &UA_TYPES[UA_TYPES_UINT32]))
        *numberOfNodes = *(UA_UInt32*)value->data;
    UA_Variant_clear(value);
    UA_Client_readValueAttribute(client, UA_NODEID_NUMERIC(1, 1001), value);
    if(UA_Variant_hasScalarType(value, &UA_TYPES[UA_TYPES_UINT32]))
        *nodesPerLevel = *(UA_UInt32*)value->data;
    UA_Variant_clear(value);
    UA_Variant_delete(value);
}

UA_NodeInfo *
UA_NodeInfo_new(void) {
    UA_NodeInfo *info = (UA_NodeInfo*)UA_malloc(sizeof(UA_NodeInfo));
    info->nodeIds = NULL;
    info->callbackIds = NULL;
    info->subMonInfo = NULL;
    return info;
}

void
UA_NodeInfo_delete(UA_NodeInfo *info) {
    for(int i = 0; i < info->numberOfSubscriptions; i++) {
        if(info->subMonInfo[i].monIds)
            UA_free(info->subMonInfo[i].monIds);
        if(info->subMonInfo[i].nodeIds)
            UA_free(info->subMonInfo[i].nodeIds);
    }
    if(info->callbackIds)
        UA_free(info->callbackIds);
    if(info->nodeIds)
        UA_free(info->nodeIds);
    if(info->subMonInfo)
        UA_free(info->subMonInfo);
    UA_free(info);
}

UA_ByteString
loadFile(const char *const path) {
    UA_ByteString fileContents = UA_STRING_NULL;

    /* Open the file */
    FILE *fp = fopen(path, "rb");
    if(!fp) {
        errno = 0; /* We read errno also from the tcp layer... */
        return fileContents;
    }

    /* Get the file length, allocate the data and read */
    fseek(fp, 0, SEEK_END);
    fileContents.length = (size_t)ftell(fp);
    fileContents.data = (UA_Byte *)UA_malloc(fileContents.length * sizeof(UA_Byte));
    if(fileContents.data) {
        fseek(fp, 0, SEEK_SET);
        size_t read = fread(fileContents.data, sizeof(UA_Byte), fileContents.length, fp);
        if(read != fileContents.length)
            UA_ByteString_clear(&fileContents);
    } else {
        fileContents.length = 0;
    }
    fclose(fp);

    return fileContents;
}

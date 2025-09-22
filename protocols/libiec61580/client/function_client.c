
#include "function_client.h"


void printSpaces(int spaces){
    int i;

    for (i = 0; i < spaces; i++)
        printf(" ");
}

void printDataDirectory(char* doRef, IedConnection con, int spaces) {
    IedClientError error;

    LinkedList dataAttributes = IedConnection_getDataDirectory(con, &error, doRef);

    //LinkedList dataAttributes = IedConnection_getDataDirectoryByFC(con, &error, doRef, MX);

    if (dataAttributes != NULL) {
        LinkedList dataAttribute = LinkedList_getNext(dataAttributes);

        while (dataAttribute != NULL) {
            char* daName = (char*) dataAttribute->data;

            printSpaces(spaces);
            printf("DA: %s\n", (char*) dataAttribute->data);

            dataAttribute = LinkedList_getNext(dataAttribute);

            char daRef[130];
            sprintf(daRef, "%s.%s", doRef, daName);
            printDataDirectory(daRef, con, spaces + 2);
        }
    }

    LinkedList_destroy(dataAttributes);
}

void getList(IedConnection con){
    printf("Get logical device list...\n");
        IedClientError error;
        LinkedList deviceList = IedConnection_getLogicalDeviceList(con, &error);

        if (error != IED_ERROR_OK) {
            printf("Failed to read device list (error code: %i)\n", error);
        }

        LinkedList device = LinkedList_getNext(deviceList);

        while (device != NULL) {
            printf("LD: %s\n", (char*) device->data);

            LinkedList logicalNodes = IedConnection_getLogicalDeviceDirectory(con, &error,
                    (char*) device->data);

            LinkedList logicalNode = LinkedList_getNext(logicalNodes);

            while (logicalNode != NULL) {
                printf("  LN: %s\n", (char*) logicalNode->data);

                char lnRef[129];

                sprintf(lnRef, "%s/%s", (char*) device->data, (char*) logicalNode->data);

                LinkedList dataObjects = IedConnection_getLogicalNodeDirectory(con, &error,
                        lnRef, ACSI_CLASS_DATA_OBJECT);

                LinkedList dataObject = LinkedList_getNext(dataObjects);

                while (dataObject != NULL) {
                    char* dataObjectName = (char*) dataObject->data;

                    printf("    DO: %s\n", dataObjectName);

                    dataObject = LinkedList_getNext(dataObject);

                    char doRef[129];

                    sprintf(doRef, "%s/%s.%s", (char*) device->data, (char*) logicalNode->data, dataObjectName);

                    printDataDirectory(doRef, con, 6);
                }

                LinkedList_destroy(dataObjects);
                
                LinkedList dataSets = IedConnection_getLogicalNodeDirectory(con, &error, lnRef,
                        ACSI_CLASS_DATA_SET);

                LinkedList dataSet = LinkedList_getNext(dataSets);

                while (dataSet != NULL) {
                    char* dataSetName = (char*) dataSet->data;
                    bool isDeletable;
                    char dataSetRef[130];
                    bool isMisura = false;
                    sprintf(dataSetRef, "%s.%s", lnRef, dataSetName);

                    LinkedList dataSetMembers = IedConnection_getDataSetDirectory(con, &error, dataSetRef,
                            &isDeletable);

                    if (isDeletable){
                        printf("    Data set: %s (deletable)\n", dataSetName);
                    }
                    else if(strcmp(dataSetName,"Measurements") == 0){
                        printf("    Data set: %s (not deletable)\n", dataSetName);
                        isMisura = true;
                    }else{
                        printf("    Data set: %s (not deletable)\n", dataSetName);
                    }
                    LinkedList dataSetMemberRef = LinkedList_getNext(dataSetMembers);

                    while (dataSetMemberRef != NULL) {

                        char* memberRef = (char*) dataSetMemberRef->data;

                        if(isMisura){
                            MmsValue* value = IedConnection_readObject(con, &error,memberRef,IEC61850_FC_MX);
                            float fval = MmsValue_toFloat(value);
                            printf("      %s - %f\n", memberRef, fval);
                        }else{
                            printf("      %s\n", memberRef);
                        }

                        dataSetMemberRef = LinkedList_getNext(dataSetMemberRef);
                    }

                    LinkedList_destroy(dataSetMembers);

                    dataSet = LinkedList_getNext(dataSet);
                }

                LinkedList_destroy(dataSets);

                LinkedList reports = IedConnection_getLogicalNodeDirectory(con, &error, lnRef,
                        ACSI_CLASS_URCB);

                LinkedList report = LinkedList_getNext(reports);

                while (report != NULL) {
                    char* reportName = (char*) report->data;

                    printf("    RP: %s\n", reportName);

                    report = LinkedList_getNext(report);
                }

                LinkedList_destroy(reports);

                reports = IedConnection_getLogicalNodeDirectory(con, &error, lnRef,
                        ACSI_CLASS_BRCB);

                report = LinkedList_getNext(reports);

                while (report != NULL) {
                    char* reportName = (char*) report->data;

                    printf("    BR: %s\n", reportName);

                    report = LinkedList_getNext(report);
                }

                LinkedList_destroy(reports);

                logicalNode = LinkedList_getNext(logicalNode);
            }

            LinkedList_destroy(logicalNodes);

            device = LinkedList_getNext(device);
        }

        LinkedList_destroy(deviceList);
}
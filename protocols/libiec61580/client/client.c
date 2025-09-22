
#include "iec61850_client.h"

#include "hal_thread.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include "function_client.h"

static IedConnection con = NULL;
static int running = 0;

void sigint_handler(int signalId){
    running = 0;
}

int main(int argc, char** argv) {
    char* hostname;
    int tcpPort = 8104;
    const char* localIp = NULL;
    int localTcpPort = -1;

    if (argc > 1){
        hostname = argv[1];
    }else{
        hostname = "localhost";
    }
    if (argc > 2)
        tcpPort = atoi(argv[2]);
    if (argc > 3)
        localIp = argv[3];

    if (argc > 4)
        localTcpPort = atoi(argv[4]);

    IedClientError error;

    /* Optional bind to local IP address/interface */
    if (localIp) {
        IedConnection_setLocalAddress(con, localIp, localTcpPort);
        printf("Bound to Local Address: %s:%i\n", localIp, localTcpPort);
    }

    running = 1;

    signal(SIGINT, sigint_handler);

    uint64_t timeStamp = Hal_getTimeInMs();

    int scelta;
    int x = 1;
    while(running){
        while(x){
            printf("1. Test connessione\n 2. Connessione persistente\n");
            scanf("%d",&scelta);
            switch (scelta){
            case 1:
                con = IedConnection_create();
                IedConnection_connect(con, &error, hostname, tcpPort);
                printf("Connecting to %s:%i\n", hostname, tcpPort);

                if (error == IED_ERROR_OK){
                    printf("Connected\n");
                }else{
                    printf("Failed to connect to %s:%i\n", hostname, tcpPort);
                    Thread_sleep(60000);
                }
                IedConnection_close(con);
                IedConnection_destroy(con);
                printf("Disconneso\n");
                break;
            
            default:
                con = IedConnection_create();
                IedConnection_connect(con, &error, hostname, tcpPort);
                printf("Connecting to %s:%i\n", hostname, tcpPort);

                if (error == IED_ERROR_OK){
                    printf("Connected\n");
                }else{
                    printf("Failed to connect to %s:%i\n", hostname, tcpPort);
                    Thread_sleep(60000);
                }
                x = 0;
                break;
            }
        }
        printf("OPZIONI:\n 1.Visualizza tutti i dispositivi\n 2.Leggi il valore float (mag.f) del dispositivio analogico GGI01.AnIn1 \n 3. ON/OFF del dispositivo digitale GGI01.SPCS01 (true = acceso, false = spento) \n 4.Esci \n");
        scanf("%d",&scelta);
        switch (scelta){
        case 1:
            getList(con);
            break;
        case 2:
            MmsValue* object_value = IedConnection_readObject(con, &error, "simpleIOGenericIO/GGIO1.AnIn1.mag.f", IEC61850_FC_MX);

            if (object_value != NULL){
                if (MmsValue_getType(object_value) == MMS_FLOAT) {
                    float fval = MmsValue_toFloat(object_value);
                    printf("read float value: %f\n", fval);
                }else if (MmsValue_getType(object_value) == MMS_DATA_ACCESS_ERROR) {
                    printf("Failed to read value (error code: %i)\n", MmsValue_getDataAccessError(object_value));
                }
                MmsValue_delete(object_value);
            }
            break;
        case 3:
            ControlObjectClient object = ControlObjectClient_create("simpleIOGenericIO/GGIO1.SPCSO1", con);
            bool modifica = true;
            while(modifica){
                char scelta_boolean[10];
                MmsValue* mmsboolean;
                printf("scegli tra true o false\n");
                scanf("%s", &scelta_boolean);
                if(strcmp(scelta_boolean,"true") == 0){
                    mmsboolean = MmsValue_newBoolean(true);
                    modifica = false;
                }else if(strcmp(scelta_boolean,"false") == 0){
                    mmsboolean = MmsValue_newBoolean(false);
                    modifica = false;
                }else{
                    printf("devi inserire true o false, %s non valido\n", scelta_boolean);
                }
                if(ControlObjectClient_operate(object,mmsboolean,timeStamp)){
                    printf("Operazione eseguita con successo\n");
                }else{
                    printf("Operazione fallita\n");
                }
            }
            break;
        default:
            running = 0;
        }
        //Thread_sleep(1000);
    }

    IedConnection_close(con);
    IedConnection_destroy(con);
    return 0;
}
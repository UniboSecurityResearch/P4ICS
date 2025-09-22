
/*
IMPLEMENTAZIONE BASICA DEL SERVER
CREAZIONE DEL SERVER ASSOCIAZIONE ALLA PORTA PER RICEVERE CONNESSIONI CLIENT
CREAZIONE MODELLO DATI
IMPLEMENTAZIONI DI FUNZIONI PER LA MODIFICA DI DATA OBJECT ANALOGICI (ANIN1) E DIGITALI (SPCS01)
*/

#include "iec61850_server.h"
#include "hal_thread.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "function_server.h"

#include "static_model.h"

static int running = 0;
IedServer iedServer;

void sigint_handler(int signalId){
    running = 0;
}

int main(int argc, char** argv){
    int tcpPort = 8104; //default

    if (argc > 1) {
        tcpPort = atoi(argv[1]);
    }

    printf("Using libIEC61850 version %s\n", LibIEC61850_getVersionString());


    /* Create new server configuration object */
    IedServerConfig config = IedServerConfig_create();

    /* Create a new IEC 61850 server instance */
    iedServer = IedServer_createWithConfig(&iedModel, NULL, config);

    //gestore di eventi che richiama la funzione controlHandlerForBinaryOutput per la gestione delle risposte ai comandi passati dal client
    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO1,
            (ControlHandler) controlHandlerForBinaryOutput,
            IEDMODEL_GenericIO_GGIO1_SPCSO1);

    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO2,
            (ControlHandler) controlHandlerForBinaryOutput,
            IEDMODEL_GenericIO_GGIO1_SPCSO2);

    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO3,
            (ControlHandler) controlHandlerForBinaryOutput,
            IEDMODEL_GenericIO_GGIO1_SPCSO3);

    IedServer_setControlHandler(iedServer, IEDMODEL_GenericIO_GGIO1_SPCSO4,
            (ControlHandler) controlHandlerForBinaryOutput,
            IEDMODEL_GenericIO_GGIO1_SPCSO4);

    //gestore di eventi che richiama la fuznione connectionHandler ogni volta che un client si connette o si disconnette
    IedServer_setConnectionIndicationHandler(iedServer, (IedConnectionIndicationHandler) connectionHandler, NULL);

    /* MMS server will be instructed to start listening for client connections.*/
    IedServer_start(iedServer, tcpPort);

    if (!IedServer_isRunning(iedServer)){
        printf("Starting server failed (maybe need root permissions or another server is already using the port)! Exit.\n");
        IedServer_destroy(iedServer);
        exit(-1);
    }

    running = 1;

    signal(SIGINT, sigint_handler);

    float t = 0.f;

    while(running){
        printf("\n");
        uint64_t timestamp = Hal_getTimeInMs();
        t += 1.f;

        Timestamp iecTimestamp;

        Timestamp_clearFlags(&iecTimestamp);
        Timestamp_setTimeInMilliseconds(&iecTimestamp, timestamp);
        Timestamp_setLeapSecondKnown(&iecTimestamp, true);

        /* toggle clock-not-synchronized flag in timestamp */
        if (((int) t % 2) == 0){
            Timestamp_setClockNotSynchronized(&iecTimestamp, true);
        }

        //modifico il valore float e il tiemstamp
        IedServer_lockDataModel(iedServer);
        IedServer_updateTimestampAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn1_t, &iecTimestamp);
        IedServer_updateFloatAttributeValue(iedServer, IEDMODEL_GenericIO_GGIO1_AnIn1_mag_f, t);
        IedServer_unlockDataModel(iedServer);

        Thread_sleep(1000);
    }
    /* stop MMS server - close TCP server socket and all client sockets */
    IedServer_stop(iedServer);

    /* Cleanup - free all resources */
    IedServer_destroy(iedServer);
    return 0;
}
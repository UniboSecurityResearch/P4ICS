#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* BACnet Stack defines - first */
#include "bacnet/bacdef.h"
/* BACnet Stack API */
#include "bacnet/bactext.h"
#include "bacnet/version.h"
/* some demo stuff needed */
#include "bacnet/basic/sys/filename.h"
#include "bacnet/basic/sys/debug.h"
#include "bacnet/basic/sys/mstimer.h"
#include "bacnet/basic/server/bacnet_basic.h"
#include "bacnet/basic/server/bacnet_port.h"
#include "bacnet/basic/object/device.h"
#include "bacnet/basic/object/ai.h"
#include "bacnet/basic/object/ao.h"
#include "bacnet/datalink/datalink.h"
#include "bacnet/datalink/dlenv.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>


static const char *Device_Name = "BACnet Smart Sensor (B-SS)"; /* nome dispositivo*/
#define SENSOR_ID 1 /* id dispositivo*/

/* struttura che definisce un oggetto BacnetObjectTable*/
struct BACnetObjectTable { 
    const uint8_t type;
    const uint8_t instance;
    const uint16_t units;
    const float value;
    const char *name;
    const char *description;
};

/* array di oggetti BACnetObjectTable*/
static struct BACnetObjectTable Object_Table[] = {
    { OBJECT_ANALOG_INPUT, SENSOR_ID, UNITS_DEGREES_CELSIUS, 25.0f, "Indoor Air Temperature", "indoor air temperature" },
    { OBJECT_ANALOG_OUTPUT, 1, UNITS_DEGREES_ANGULAR, 12.0f, "VAV Actuator", "variable air valve actuator" },
    { OBJECT_ANALOG_OUTPUT, 2, UNITS_DEGREES_CELSIUS, 25.0f, "Temperature Setpoint", "indoor air temperature setpoint" },
};

/* timer per aggiornare il valore del sensore */
static struct mstimer Sensor_Update_Timer;

/**
 * @brief BACnet Project Initialization Handler
 * @param context [in] The context to pass to the callback function
 * @note This is called from the BACnet task
 */

 //funzione che crea 3 oggetti bacnet
static void BACnet_Object_Table_Init(void *context){
    unsigned i;
    (void)context;
    Analog_Input_Init();
    Analog_Output_Init();
    /* initialize child objects for this basic sample */
    for (i = 0; i < ARRAY_SIZE(Object_Table); i++) {
        switch (Object_Table[i].type) {
            case OBJECT_ANALOG_INPUT:
                Analog_Input_Create(Object_Table[i].instance);
                Analog_Input_Name_Set(Object_Table[i].instance, Object_Table[i].name);
                Analog_Input_Present_Value_Set(Object_Table[i].instance, Object_Table[i].value);
                Analog_Input_Units_Set(Object_Table[i].instance, Object_Table[i].units);
                Analog_Input_Description_Set(Object_Table[i].instance, Object_Table[i].description);
                break;
            case OBJECT_ANALOG_OUTPUT:
                Analog_Output_Create(Object_Table[i].instance);
                Analog_Output_Name_Set(Object_Table[i].instance, Object_Table[i].name);
                Analog_Output_Description_Set(Object_Table[i].instance, Object_Table[i].description);
                Analog_Output_Units_Set(Object_Table[i].instance, Object_Table[i].units);
                Analog_Output_Relinquish_Default_Set(Object_Table[i].instance, Object_Table[i].value);
                break;
            default:
                break;
        }
    }
    /* start the seconds cyclic timer */
    mstimer_set(&Sensor_Update_Timer, 1000);
    srand(0);
}

/**
 * @brief BACnet Project Task Handler
 * @param context [in] The context to pass to the callback function
 * @note This is called from the BACnet task
 */

 //funzione che simula un cambio di temperatura di un sesnsore ogni secondo
static void BACnet_Object_Task(void *context){
    float temperature = 0.0f, change = 0.0f;

    (void)context;
    if (mstimer_expired(&Sensor_Update_Timer)) {
        mstimer_reset(&Sensor_Update_Timer);
        /* simulate a sensor reading, and update the BACnet object values */
        if (Analog_Input_Out_Of_Service(SENSOR_ID)) {
            return;
        }
        temperature = Analog_Input_Present_Value(SENSOR_ID); //legge il valore della temperatura
        change = -1.0f + 2.0f * ((float)rand()) / RAND_MAX;
        temperature += change; //cambia valore temperatura
        Analog_Input_Present_Value_Set(SENSOR_ID, temperature); //setta il nuovo valore della temperatura
        printf("Temperatura: %f\n",temperature);
    }
}

/**
 * @brief Store the BACnet data after a WriteProperty for object property
 * @param object_type - BACnet object type
 * @param object_instance - BACnet object instance
 * @param object_property - BACnet object property
 * @param array_index - BACnet array index
 * @param application_data - pointer to the data
 * @param application_data_len - length of the data
 */

//funzione che memorizza le operazioni del client sul server, da implementare
static void BACnet_Basic_Store(
    BACNET_OBJECT_TYPE object_type,
    uint32_t object_instance,
    BACNET_PROPERTY_ID object_property,
    BACNET_ARRAY_INDEX array_index,
    uint8_t *application_data,
    int application_data_len)
{
    (void)array_index;
    (void)application_data;
    (void)application_data_len;
    debug_printf_stdout(
        "BACnet Store: %s[%lu]-%s\n", bactext_object_type_name(object_type),
        (unsigned long)object_instance, bactext_property_name(object_property));
}

/** Main function of server demo.
 *0
 * @see Device_Set_Object_Instance_Number, dlenv_init, Send_I_Am,
 *      datalink_receive, npdu_handler,
 *      dcc_timer_seconds, datalink_maintenance_timer,
 *      handler_cov_task, tsm_timer_milliseconds
 *
 * @param argc [in] Arg count.
 * @param argv [in] Takes one argument: the Device Instance #.
 * @return 0 on success.
 */

int main(int argc, char const *argv[]){
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char server_message[2000], client_message[2000];
    socklen_t client_len = sizeof(client_addr);
    float value;
    char object_type[32];
    char device_id[32];
    uint8_t instance;
    float read_value;

     // Crea socket UDP 
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Errore nella creazione della socket");
        exit(-1);
    }

    // Configurazione della socket
    memset(&server_addr, 0, sizeof server_addr);
    server_addr.sin_family = AF_INET; // IPv4
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(47808); // Server Port

    if (argc > 1) {
        /* allow the device ID to be set */
        Device_Set_Object_Instance_Number(strtol(argv[1], NULL, 0));
    }
    if (argc > 2) {
        /* allow the device name to be set */
        Device_Name = argv[2];
    }

    Device_Object_Name_ANSI_Init(Device_Name);
    debug_printf_stdout("BACnet Device: %s\n", Device_Name);
    debug_printf_stdout("BACnet Stack Version %s\n", BACNET_VERSION_TEXT);
    debug_printf_stdout("BACnet Stack Max APDU: %d\n", MAX_APDU);

    // Bind socket
    if ((bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr))) == -1) {
        close(sockfd);
        perror("Errore nel bind");
    }

    printf("Server partito...\n");

    /* inizializza oggetti BACnet chiamando direttamente la callback */
    BACnet_Object_Table_Init(NULL);
    while(1){
        BACnet_Object_Task(NULL);
        int bytes_received = recvfrom(sockfd, client_message, sizeof(client_message), 0, (struct sockaddr*)&client_addr, &client_len);

        if (bytes_received < 0) {
            perror("Errore ricezione");
        }

        printf("Richiesta inviata da IP: %s e porta: %i\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        printf("Messaggio ricevuto: %s\n", client_message);

        char *token = strtok(client_message, " ");
        if (token && strcmp(token, "READ") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                strncpy(device_id, token, sizeof(device_id));
                token = strtok(NULL, " ");
                if (token) {
                    strncpy(object_type, token, sizeof(object_type));
                    token = strtok(NULL, " ");
                    if (token) {
                        instance = (unsigned int)strtoul(token, NULL, 10);
                        printf("Device ID: %s, Object Type: %s, Instance: %u\n", device_id, object_type, instance);
                        // qui puoi continuare con la logica
                        if(strcmp(object_type, "analog-input") == 0){
                            value = Analog_Input_Present_Value(instance);
                            snprintf(server_message,sizeof(server_message), "analog-input %u = %.2f", instance, value);
                             // Invia richiesta al server
                            if (sendto(sockfd, server_message, strlen(server_message), 0, (struct sockaddr *)&client_addr, client_len) < 0) {
                                perror("Errore invio");
                                close(sockfd);
                                return 1;   
                            }
                        }
                    } else {
                        printf("Errore: manca instance\n");
                    }
                } else {
                    printf("Errore: manca object_type\n");
                }
            } else {
                printf("Errore: manca device_id\n");
            }
        } else if(token && strcmp(token, "WRITE") == 0){
            token = strtok(NULL, " ");

            if (token) {
                strncpy(device_id, token, sizeof(device_id));
                token = strtok(NULL, " ");

                if (token) {
                    strncpy(object_type, token, sizeof(object_type));
                    token = strtok(NULL, " ");

                    if (token) {
                        instance = (unsigned int)strtoul(token, NULL, 10);

                        // qui puoi continuare con la logica
                        if(strcmp(object_type, "analog-output") == 0){
                            token = strtok(NULL, " ");
                            read_value = (float)strtof(token, NULL);
                            printf("Device ID: %s, Object Type: %s, Instance: %u, Read_value: %.2f\n", device_id, object_type, instance, read_value);
                            float old_value = Analog_Output_Present_Value(instance);
                            if(!Analog_Output_Present_Value_Set(instance,read_value,8)){
                                printf("Errore nello scrivere il valore\n");
                                snprintf(server_message,sizeof(server_message), "Valore: %.2f NON scritto correttamente", read_value);
                            }else{
                                printf("Valore: %.2f scritto correttamente\n",read_value);
                                snprintf(server_message,sizeof(server_message), "Valore: %.2f scritto in analog-output: %u", read_value, instance);
                                printf("Valore modificato da %.2f a %.2f\n",old_value, Analog_Output_Present_Value(instance));
                                 // Invia richiesta al server
                                if (sendto(sockfd, server_message, strlen(server_message), 0, (struct sockaddr *)&client_addr, client_len) < 0) {
                                    perror("Errore invio");
                                    close(sockfd);
                                    return 1;
                                }
                            }
                        }
                    } else{
                        printf("Errore: manca instance\n");
                    } 
                } else{
                    printf("Errore: manca object_type\n");
                }
            }else{
                printf("Errore: manca device_id\n");
            }
        }else if(token && strcmp(token, "PING") == 0){
            snprintf(server_message,sizeof(server_message), "risposta al ping");
            printf("\nping arrivato al server\n");
            // Invia richiesta al server
            if (sendto(sockfd, server_message, strlen(server_message), 0, (struct sockaddr *)&client_addr, client_len) < 0) {
                perror("Errore invio");
                close(sockfd);
                return 1;
            }
        } else{
            printf("Errore: comando non riconosciuto o malformato\n");

        }
    }
    close(sockfd);
    return 0;
}

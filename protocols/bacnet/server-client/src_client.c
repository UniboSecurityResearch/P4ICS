/**
 * @file
 * @author Steve Karg
 * @date 2022
 * @brief Application to acquire data from a target client
 *
 * SPDX-License-Identifier: MIT
 */

#include <sys/time.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
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
#include "bacnet/basic/client/bac-task.h"
#include "bacnet/basic/client/bac-data.h"
#include "bacnet/basic/object/device.h"
#include "bacnet/datalink/datalink.h"
#include "bacnet/datalink/dlenv.h"
#include <arpa/inet.h>
#include <sys/socket.h>

/* print with flush by default */
#define PRINTF debug_printf_stdout

/* current version of the BACnet stack */
static const char *BACnet_Version = BACNET_VERSION_TEXT;

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 47808
#define BUFFER_SIZE 1024
#define POLL_INTERVAL_SEC 5  // intervallo in secondi tra ogni polling

static void print_usage(const char *filename)
{
    PRINTF("Usage: %s [device-instance]\n", filename);
    PRINTF("       [object-type] [object-instance]\n");
    PRINTF("       [--device][--print-seconds]\n");
    PRINTF("       [--version][--help]\n");
}

static void print_help(){
    PRINTF("Simulate a BACnet server-client device.\n");
    PRINTF("1)Ping-al-server:\n"
           "Invia una richiesta generica al server che ti \n"
           "rispondera con una risposta generica, utilizzata\n"
           "per verificare la velocita di comunicazione\n");
    PRINTF("\n");
    PRINTF("2)lettura-valore:\n"
           "Invia una richiesta al server per leggere un valore, \n"
           "che risponderà, in questo esempio, con la temperatura\n"
           "di un Analog-Input. Richiamata più volte il valore della\n"
           "temperatura cambierà.\n");
    PRINTF("\n");
    PRINTF("3)Scrittura-valore:\n"
           "Invia una richiesta al server per andare ad impostare una\n"
           "temperatura, chiesta in input all utente, in un \n"
           "Analog-Output.\n");
    PRINTF("\n");
}

/**
 * @brief Main function of server-client demo.
 * @param argc [in] Arg count.
 * @param argv [in] Takes one argument: the Device Instance #.
 * @return 0 on success.
 */

 int main(int argc, char const *argv[]){
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    // Leggi parametri da linea di comando
    char *device_id = argv[1];
    printf("devidece id: %s\n",device_id);
    char *object_type = argv[2];
    uint32_t object_instance = atoi(argv[3]);   

    // Crea messaggio di richiesta
    char request[BUFFER_SIZE];
    

    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[1024];
    socklen_t addr_len = sizeof(server_addr);

    // Creazione socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Specifica indirizzo server
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    printf("Client partito...\n");

    print_help();
    int x = 0;
    while (x == 0){
        int scelta;

        printf("1 - Ping al server\n2 - Lettura valore\n3 - Scrittura valore\n4 - chiusura client\n\n");
        scanf("%d",&scelta);

        switch (scelta)
        {
        case 1:{
            struct timeval t_inizio, t_fine;
            snprintf(request, sizeof(request), "PING");


            // Invia richiesta al server
            gettimeofday(&t_inizio, NULL);
            if (sendto(sockfd, request, strlen(request), 0, (struct sockaddr *)&server_addr, addr_len) < 0) {
                perror("Errore invio");
                close(sockfd);
                return 1;   
            }

            // Riceve risposta
            char response[BUFFER_SIZE] = {0};
            if (recvfrom(sockfd, response, sizeof(response) - 1, 0, (struct sockaddr *)&server_addr, &addr_len) < 0) {
                perror("Errore ricezione");
                close(sockfd);
                return 1;
            }
            gettimeofday(&t_fine, NULL);
            long microsecondi = t_fine.tv_usec - t_inizio.tv_usec;



            printf("Risposta dal server: %s, in %ld micro-secondi\n\n", response, microsecondi);
        
        

            break;
        }
        case 2:

            snprintf(request, sizeof(request), "READ %s %s %u", device_id, "analog-input", object_instance);


            // Invia richiesta al server
            if (sendto(sockfd, request, strlen(request), 0, (struct sockaddr *)&server_addr, addr_len) < 0) {
                perror("Errore invio");
                close(sockfd);
                return 1;   
            }

            // Riceve risposta
            char response[BUFFER_SIZE] = {0};
            if (recvfrom(sockfd, response, sizeof(response) - 1, 0, (struct sockaddr *)&server_addr, &addr_len) < 0) {
                perror("Errore ricezione");
                close(sockfd);
                return 1;
            }

            printf("Risposta dal server: %s\n\n", response);
            
            break;

        case 3: {
                float valore = 0;
                while (1) {
                    printf("inserisci il valore da scrivere al server:\n");
                    scanf("%f", &valore);
                    if (valore > 0)
                        break;
                }
            
                snprintf(request, sizeof(request), "WRITE %s %s %u %f", device_id, "analog-output", object_instance, valore);
            
                // Invia richiesta al server
                if (sendto(sockfd, request, strlen(request), 0, (struct sockaddr *)&server_addr, addr_len) < 0) {
                    perror("Errore invio");
                    close(sockfd);
                    return 1;   
                }
            
                // Riceve risposta
                char response[BUFFER_SIZE] = {0};
                if (recvfrom(sockfd, response, sizeof(response) - 1, 0, (struct sockaddr *)&server_addr, &addr_len) < 0) {
                    perror("Errore ricezione");
                    close(sockfd);
                    return 1;
                }
            
                printf("Risposta dal server: %s\n\n", response);
            
                break;
        }
        case 4:
            x = 1;
            printf("chiusura client...\n");
            break;

        default:
            break;

        
        }
    }
    close(sockfd);
    return 0;
}
 
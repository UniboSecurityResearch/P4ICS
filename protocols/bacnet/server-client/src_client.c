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

//range valori write
#define MIN_RANGE 20
#define MAX_RANGE 30
//ripetizioni loop test
#define REP 10000
#define BUFFER_SIZE 1024
#define POLL_INTERVAL_SEC 5  // intervallo in secondi tra ogni polling

static void print_usage(const char *filename)
{
    PRINTF("Usage: %s [device-instance]\n", filename);
    PRINTF("       [object-type (analog-input)] [object-instance (1)]\n");
    PRINTF("       [ip-server (127.0.0.1)][server-port (47808)]\n");
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
    int i = 0;
    if (argc < 6) {
        print_usage(argv[0]);
        return 1;
    }

    // Leggi parametri da linea di comando
    char *device_id = argv[1];
    printf("devidece id: %s\n",device_id);
    char *object_type = argv[2];
    uint32_t object_instance = atoi(argv[3]);  
    char *SERVER_IP = argv[4];
    int SERVER_PORT = atoi(argv[5]);

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

    char *nomi_file[] = {
        "test_PING.txt",
        "test_READ.txt",
        "test_WRITE.txt"
    };

    int numero_file = sizeof(nomi_file) / sizeof(nomi_file[0]);

    for (i = 0; i < numero_file; i++) {
        FILE *fp = fopen(nomi_file[i], "w");

        if (fp == NULL) {
            perror("Errore nell'apertura del file");
            fprintf(stderr, "Impossibile creare il file: %s\n", nomi_file[i]);
            return 1;
        }

        if (fclose(fp) == EOF) {
            perror("Errore nella chiusura del file");
            return 1;
        }
        printf("File creato con successo: %s\n", nomi_file[i]);
    }

    printf("Client partito...\n");

    print_help();
    int x = 0;
    while (x == 0){
        int scelta;

        printf("1 - Ping al server\n2 - Lettura valore\n3 - Scrittura valore\n4 - test loop PING\n5 - test loop READ\n6 - test loop WRITE\n7 - chiusura client\n\n");
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


            // Apri "test_PING.txt" in modalità append ("a")
            FILE *fp_uno = fopen("test_PING.txt", "a");
            if (fp_uno == NULL) {
                perror("Errore nell'apertura di test_PING.txt per la scrittura");
                return 1;
            }
    
            // Scrivi il valore nel file.
            fprintf(fp_uno, "%d\n", microsecondi); 
    
            // Chiudi il file
            if (fclose(fp_uno) == EOF) {
                perror("Errore nella chiusura di test_PING.txt dopo la scrittura");
                return 1;
            }

            break;
        }
        case 2:{
            struct timeval t_inizio, t_fine;
            snprintf(request, sizeof(request), "READ %s %s %u", device_id, "analog-input", object_instance);


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
            
            // Apri "test_READ.txt" in modalità append ("a")
            FILE *fp_uno = fopen("test_READ.txt", "a");
            if (fp_uno == NULL) {
                perror("Errore nell'apertura di test_READ.txt per la scrittura");
                return 1;
            }
    
            // Scrivi il valore nel file.
            fprintf(fp_uno, "%d\n", microsecondi); 
    
            // Chiudi il file
            if (fclose(fp_uno) == EOF) {
                perror("Errore nella chiusura di test_READ.txt dopo la scrittura");
                return 1;
            }

            break;
        }
        case 3: {
            struct timeval t_inizio, t_fine;
            float valore = 0;
            while (1) {
                printf("inserisci il valore da scrivere al server:\n");
                scanf("%f", &valore);
                if (valore > 0)
                    break;
            }
            
            snprintf(request, sizeof(request), "WRITE %s %s %u %f", device_id, "analog-output", object_instance, valore);
            
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
                
            // Apri "test_WRITE.txt" in modalità append ("a")
            FILE *fp_uno = fopen("test_WRITE.txt", "a");
            if (fp_uno == NULL) {
                perror("Errore nell'apertura di test_WRITE.txt per la scrittura");
                return 1;
            }
    
            // Scrivi il valore nel file. 
            fprintf(fp_uno, "%d\n", microsecondi); 
    
            // Chiudi il file
            if (fclose(fp_uno) == EOF) {
                perror("Errore nella chiusura di test_WRITE.txt dopo la scrittura");
                return 1;
            }

            break;
        }
        //loop ping
        case 4:{
            struct timeval t_inizio, t_fine;

            // Apri "test_PING.txt" in modalità append ("a")
            FILE *fp_uno = fopen("test_PING.txt", "a");
            if (fp_uno == NULL) {
                perror("Errore nell'apertura di test_PING.txt per la scrittura");
                return 1;
            }

            for (i = 0; i < REP; i++)
            {
            
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


                // Scrivi il valore nel file.
                fprintf(fp_uno, "%d\n", microsecondi); 
    
            }

            // Chiudi il file
            if (fclose(fp_uno) == EOF) {
                perror("Errore nella chiusura di test_PING.txt dopo la scrittura");
                return 1;
            }

            break;
        }
        //loop write
        case 5:{
            struct timeval t_inizio, t_fine;

            // Apri "test_READ.txt" in modalità append ("a")
            FILE *fp_uno = fopen("test_READ.txt", "a");
            if (fp_uno == NULL) {
                perror("Errore nell'apertura di test_READ.txt per la scrittura");
                return 1;
            }

            for(i = 0; i < REP; i++)
            {
            
                snprintf(request, sizeof(request), "READ %s %s %u", device_id, "analog-input", object_instance);


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



                // Scrivi il valore nel file.
                fprintf(fp_uno, "%d\n", microsecondi); 
    
            }

            // Chiudi il file
            if (fclose(fp_uno) == EOF) {
                perror("Errore nella chiusura di test_READ.txt dopo la scrittura");
                return 1;
            }

            break;
        }
        //loop write
        case 6:{
            struct timeval t_inizio, t_fine;

            // Apri "test_WRITE.txt" in modalità append ("a")
            FILE *fp_uno = fopen("test_WRITE.txt", "a");
            if (fp_uno == NULL) {
            perror("Errore nell'apertura di test_WRITE.txt per la scrittura");
            return 1;
            }
            
            srand((unsigned int)time(NULL));

            for (i = 0; i < REP; i++)
            {
            
                float valore = 0;
                //per comodita geneero un numero casuale compreso tra MIN_RANGE e MAX_RANGE senza doverlo chiedere ogni volta
                float random_norm = (float)rand() / (float)RAND_MAX;
                valore = MIN_RANGE + random_norm * (MAX_RANGE - MIN_RANGE);
            
                snprintf(request, sizeof(request), "WRITE %s %s %u %f", device_id, "analog-output", object_instance, valore);
            
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


                // Scrivi il valore nel file.
                fprintf(fp_uno, "%d\n", microsecondi); 
    
            }

            // Chiudi il file
            if (fclose(fp_uno) == EOF) {
                perror("Errore nella chiusura di test_WRITE.txt dopo la scrittura");
                return 1;
            }

            break;
        }
        case 7:
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
 
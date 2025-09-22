#ifndef FUNCTIONCLIENT_H
#define FUNCTIONCLIENT_H

#include "hal_thread.h"
#include "iec61850_client.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "static_model.h"

void printSpaces(int spaces);
void printDataDirectory(char* doRef, IedConnection con, int spaces);
void getList(IedConnection con);
#endif

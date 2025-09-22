#ifndef FUNCTIONSERVER_H
#define FUNCTIONSERVER_H

#include "iec61850_server.h"
#include "hal_thread.h"
#include "iec61850_client.h"
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "static_model.h"

ControlHandlerResult controlHandlerForBinaryOutput(ControlAction action, void* parameter, MmsValue* value, bool test);
void connectionHandler (IedServer self, ClientConnection connection, bool connected, void* parameter);

#endif

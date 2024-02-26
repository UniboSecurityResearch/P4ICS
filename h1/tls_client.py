from pymodbus.client import AsyncModbusTlsClient
import asyncio
import time
import random

# async def main():
#     client = AsyncModbusTlsClient("200.1.1.7", 5020, certfile="./cert.crt", keyfile="./key.key")
#     await client.connect()
#     register_id = 0
#     new_value = 45
#     with open("/shared/results_tls_read.txt", "w") as results_file:
#         for j in range(10):
#             for i in range(10000):
#                 #new_value = random.randint(0, 100)
#                 time_start = time.time()
#                 #await client.write_register(register_id, new_value, unit=0x01) 
#                 await client.read_holding_registers(register_id, 1, unit=0x01) #response = await client.read_holding_registers(register_id, 1, unit=0x01)
#                 time_end = time.time()
#                 results_file.write("%s\n" % (time_end - time_start))
#                 print(f"Valore letto dal registro  - {i}")
#                 #print(f"Valore scritto nel registro {register_id}: {new_value} - {i}")
#     client.close()

# asyncio.run(main())


###### TEST OPEN CONNECTION ######
async def main():
    client = AsyncModbusTlsClient("200.1.1.7", 5020, certfile="./cert.crt", keyfile="./key.key")
    with open("/shared/results_conn_tls.txt", "w") as results_file:
        for i in range(10000):
            time_start = time.time()
            await client.connect()
            time_end = time.time()
            results_file.write("%s\n" % (time_end - time_start))
            client.close()
            print(f"Test connection number {i}")
asyncio.run(main())
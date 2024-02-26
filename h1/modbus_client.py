from pymodbus.client import AsyncModbusTcpClient
import asyncio
import time

###### TEST PPT E DEQ in Switch ######
# async def main():
#     client = AsyncModbusTcpClient("200.1.1.7", 502)
#     await client.connect()
#     register_id = 0
#     new_value = 45
#     for j in range(10):
#         for i in range(10000):
#             #await client.write_register(register_id, new_value, unit=0x01)
#             #print(f"Valore scritto nel registro {register_id}: {new_value} - {i}")
#             await client.read_holding_registers(register_id, 1, unit=0x01) #response = await client.read_holding_registers(register_id, 1, unit=0x01)
#             print(f"Valore letto dal registro - {i}")
#     client.close()

# asyncio.run(main())

###### TEST AVG TIME ######
# async def main():
#     client = AsyncModbusTcpClient("200.1.1.7", 502)
#     await client.connect()
#     register_id = 0
#     new_value = 45
#     with open("/shared/results_10*10000_no_chiper_write.txt", "w") as results_file:
#         for j in range(10):
#             for i in range(10000):
#                 time_start = time.time()
#                 #new_value = random.randint(0, 100)
#                 await client.write_register(register_id, new_value, unit=0x01) 
#                 #await client.read_holding_registers(register_id, 1, unit=0x01) #response = await client.read_holding_registers(register_id, 1, unit=0x01)
#                 time_end = time.time()
#                 results_file.write("%s\n" % (time_end - time_start))
#                 #print(f"Valore letto dal registro {register_id} - {i}") #print(f"Valore letto dal registro {register_id}: {response.registers[0]} - {i}")
#                 print(f"Valore scritto nel registro {register_id}: {new_value} - {i}")
#     client.close()

# asyncio.run(main())


###### TEST OPEN CONNECTION ######
async def main():
    client = AsyncModbusTcpClient("200.1.1.7", 502)
    with open("/shared/results_conn.txt", "w") as results_file:
        for i in range(10000):
            time_start = time.time()
            await client.connect()
            time_end = time.time()
            results_file.write("%s\n" % (time_end - time_start))
            client.close()
            print(f"Test connection number {i}")
asyncio.run(main())


# async def main():
#     client = AsyncModbusTcpClient("200.1.1.7", 502)
#     await client.connect()
#     register_id = 0
#     new_value = 45
#     await client.write_register(register_id, new_value, unit=0x01)
#     print(f"Valore scritto nel registro {register_id}: {new_value}")
#     await client.read_holding_registers(register_id, 1, unit=0x01) #response = await client.read_holding_registers(register_id, 1, unit=0x01)
#     print(f"Valore letto dal registro")
#     client.close()

# asyncio.run(main())


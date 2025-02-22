from pymodbus.client import AsyncModbusTcpClient
import asyncio
import time
import argparse
import sys
import random

def validate_key_size(value):
    valid_sizes = ['128', '160', '192', '224', '256']
    if value not in valid_sizes:
        raise argparse.ArgumentTypeError(
            f'Invalid key size. Must be one of: {", ".join(valid_sizes)}'
        )
    return value

parser = argparse.ArgumentParser(description="ModBus sample client")
parser.add_argument(
    "--write", help="If set writes to a register", action="store_true", required=False
)
parser.add_argument(
    "--read", help="If set reads from a register", action="store_true", required=False
)
parser.add_argument(
    "--rw",
    help="If set writes to a register and then reads from a register",
    action="store_true",
    required=False,
)
parser.add_argument(
    "--connect",
    help="If set connect only to the server",
    action="store_true",
    required=False,
)
parser.add_argument(
    "--connect-times",
    help="Thrift server port for table updates",
    action="store",
    default=1,
)
parser.add_argument(
    "--test-rtt",
    help="Test the Round Trip Time for 100000 times. Key size must be: 128, 160, 192, 224, or 256",
    type=validate_key_size,
    metavar="KEY_SIZE",
)
parser.add_argument(
    "--test-ppt",
    help="Test the Packet Processing Time for 100000 times",
    action="store_true",
    required=False,
)
parser.add_argument(
    "--test-deq",
    help="Test the Packet Dequeuing Time for 100000 times",
    action="store_true",
    required=False,
)


args = parser.parse_args()

##ORIGINAL
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


###### TEST OPEN CONNECTION ######
async def connect():
    client = AsyncModbusTcpClient("200.1.1.7", 502)
    with open("/shared/results_conn.txt", "w") as results_file:
        for i in range(args.connect_times):
            time_start = time.time()
            await client.connect()
            time_end = time.time()
            results_file.write("%s\n" % (time_end - time_start))
            client.close()
            print(f"Test connection number {i}")


async def write_register():
    client = AsyncModbusTcpClient("200.1.1.7", 502, retries=0)
    await client.connect()
    register_id = 0
    new_value = 45
    await client.write_register(register_id, new_value, unit=0x01)
    print(f"Valore scritto nel registro {register_id}: {new_value}")
    client.close()


async def read_register():
    client = AsyncModbusTcpClient("200.1.1.7", 502, retries=0)
    await client.connect()
    register_id = 0
    response = await client.read_holding_registers(register_id, 1, unit=0x01)
    print(f"Valore letto dal registro {register_id}: {response.registers[0]}")
    client.close()

async def test_rtt():
    client = AsyncModbusTcpClient("200.1.1.7", 502)
    await client.connect()
    register_id = 0
    new_value = 45
    key = sys.argv[2]

    ## READ
    with open(f"/shared/results_10*10000_no_chiper_read_{key}_bit_key.txt", "w") as results_file:
        for j in range(10):
            for i in range(10000):
                time_start = time.time()
                response = await client.read_holding_registers(register_id, 1, unit=0x01)
                time_end = time.time()
                results_file.write("%s\n" % (time_end - time_start))
                print(f"RTT - Value read from the register {register_id}: {response.registers[0]} - {i} - Test for {key}-bit key")

    ## WRITE
    with open(f"/shared/results_10*10000_no_chiper_write_{key}_bit_key.txt", "w") as results_file:
        for j in range(10):
            for i in range(10000):
                new_value = random.randint(0, 100)
                time_start = time.time()
                await client.write_register(register_id, new_value, unit=0x01) 
                time_end = time.time()
                results_file.write("%s\n" % (time_end - time_start))
                print(f"RTT - Value written into the register {register_id}: {new_value} - {i} - Test for {key}-bit key")
    client.close()

async def test_ppt_deq():
    client = AsyncModbusTcpClient("200.1.1.7", 502)
    await client.connect()
    register_id = 0
    new_value = 45
    for j in range(10):
        for i in range(10000):
            response = await client.read_holding_registers(register_id, 1, unit=0x01)
            print(f"PPT-DEQ - Value read from the register {register_id}: {response.registers[0]} - {i} - Test for {key}-bit key")
    client.close()


if args.write:
    asyncio.run(write_register())
elif args.read:
    asyncio.run(read_register())
elif args.rw:
    asyncio.run(read_register())
    asyncio.run(write_register())
    asyncio.run(read_register())
elif args.connect:
    asyncio.run(connect())
elif args.test_rtt:
    asyncio.run(test_rtt())
elif args.test_ppt:
    asyncio.run(test_ppt_deq())
elif args.test_deq:
    asyncio.run(test_ppt_deq())

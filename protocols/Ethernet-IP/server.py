import os
import subprocess
import sys

# Avvia un server EtherNet/IP sul IP:porta specificati con un tag "Sensor" di tipo INT.
# ENIP_ADDRESS sostituisce l'indirizzo di default (es. nel laboratorio Kathara).
subprocess.run([
    sys.executable, "-m", "cpppo.server.enip",
    "--address", os.environ.get("ENIP_ADDRESS", "192.168.100.102:44818"),
    "Sensor=INT"
])

import subprocess

# Avvia un server EtherNet/IP sul IP:porta specificati con un tag "Sensor" di tipo INT.
subprocess.run([
    "python", "-m", "cpppo.server.enip", 
    "--address", "192.168.100.102:44818", 
    "Sensor=INT"
])

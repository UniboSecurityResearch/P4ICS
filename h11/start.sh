#!/bin/sh

if [ -z "$2" ]; then
  REDIRECT=/dev/stdout
else
  REDIRECT="$2"
fi

for i in $(seq 0 $1); do
  python3 mqtt_client.py $i & > $REDIRECT
#  ./venv/bin/python3 h11/mqtt_client.py $i & > $REDIRECT
done


echo Finished scheduling

wait

echo Finished executing
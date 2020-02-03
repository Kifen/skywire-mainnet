#!/usr/bin/env bash

mkdir -p ./logs
echo Press Ctrl-C to exit
for ((;;))
do 
	./bin/skywire-visor ./integration/intermediary-visorB.json --tag VisorB 2>> ./logs/visorB.log >> ./logs/visorB.log &
	echo visor starting VisorB
	sleep 25
	echo Killing VisorB on $(ps aux |grep "[V]isorB" |awk '{print $2}')
	kill $(ps aux |grep "[V]isorB" |awk '{print $2}')
	sleep 3
	echo Restarting VisorB
done

#!/bin/sh

make txtime

for i in $(find /dev/ -name 'ttyUSB*'); 
do
	gnome-terminal -x sh -c "make txtime.upload PORT=$i && make login PORT=$i && make txtime.upload PORT=$i && make login PORT=$i"
	sleep .5
done

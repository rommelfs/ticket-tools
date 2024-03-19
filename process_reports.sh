#!/bin/bash

while  [ 1 ]
do
  ./get-reports.sh shadowserver-variot
  ./get-reports.sh shadowserver
  ./get-reports.sh cert-bund 
  sleep 3600 
done

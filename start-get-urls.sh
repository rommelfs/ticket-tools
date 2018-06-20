#!/bin/bash
while [ 1 ]
do
  echo "MS URLS:"
  ./get-ms-urls.sh
  echo "URL mon:"
  ./get-urlmon-urls.sh
  echo "URLQuery:"
  ./get-urlquery-urls.sh
  echo "Now sleeping..."
  sleep 1800 
done

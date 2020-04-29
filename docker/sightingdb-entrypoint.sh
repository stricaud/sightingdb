#!/bin/bash

if [ -z $SIGHTINGDB_APIKEY ]
then
    echo "The environment variable SIGHTINGDB_API is not set, so we leave the default to 'changeme'."
    /opt/sightingdb/target/release/sightingdb
else
    /opt/sightingdb/target/release/sightingdb -k $SIGHTINGDB_APIKEY    
fi

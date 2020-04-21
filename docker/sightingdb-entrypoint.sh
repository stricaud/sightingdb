#!/bin/bash

/opt/sightingdb/target/release/sightingdb
if [ -z $SIGHTINGDB_APIKEY ]
then
    echo "The environment variable SIGHTINGDB_API is not set, so we leave the default to 'changeme'."
else
    curl -k -H "Authorization: changeme" "https://localhost:9999/w/_config/acl/apikeys/$SIGHTINGDB_APIKEY?val="""
    curl -k -H "Authorization: $SIGHTINGDB_APIKEY" "https://localhost:9999/d/_config/acl/apikeys/changeme?val="""
fi

sightingdb_pid=$(ps |grep [s]ightingdb |cut -d' ' -f3)
wait $sightingdb_pid


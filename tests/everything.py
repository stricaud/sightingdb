#!/usr/bin/env python3
import sightingdb
import sys
import json

print(sightingdb.__file__)

con = sightingdb.connection(host="localhost", apikey="changeme")
con.disable_ssl_warnings()

deleter = sightingdb.delete(con)
deleter.delete("/_tests/namespace")
deleter.delete("/other/namespace")
deleter.delete("/your/namespace")

writer = sightingdb.writer(con)
writer.add("/namespace", "127.0.0.1", timestamp=5555)
writer.add("/other/namespace", "127.0.0.1", timestamp=1587364370)
writer.add("/other/namespace", "127.0.0.1")
writer.add("/your/namespace", "172.16.0.23")
try:
    writer.commit()
except:
    print("SightingDB is not listening to localhost:9999. Please start it so we can run our tests")
    sys.exit(1)


def test_one_read(reader, namespace=None, value=None, first_seen=None, consensus=None):
    got_one_false = False
    out = reader.read_one(namespace, value)
    print(str(out)+": ", end="")
    try:
        if value:
            if out["value"] != value:
                got_one_false = True
        if first_seen:
            if out["first_seen"] != first_seen:
                got_one_false = True
        if consensus:
            if out["consensus"] != consensus:
                got_one_false = True
    except:
        got_one_false = True
                
    if got_one_false:
        print("\033[91mERROR\033[0m")
    else:
        print("\033[92mOK\033[0m")

con = sightingdb.connection(host="localhost", apikey="changeme")
reader = sightingdb.reader(con)

test_one_read(reader, namespace="/namespace", value="127.0.0.1", first_seen=5555, consensus=2)
test_one_read(reader, namespace="/other/namespace", value="127.0.0.1", consensus=2)
test_one_read(reader, namespace="/other/namespace", value="127.0.0.1", consensus=2)
test_one_read(reader, namespace="/your/namespace", value="172.16.0.23", consensus=1)

    

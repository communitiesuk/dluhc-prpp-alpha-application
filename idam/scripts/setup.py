#!/usr/bin/python

import sys
import requests
import json
import pprint

pp = pprint.PrettyPrinter(indent=4)

print("Argument List:", str(sys.argv))

try:
    env = sys.argv[1]
except IndexError:
    print(
        """
        Help
        ====

        python3 setup.py <env> <read/write> <api_key>

        Make sure you call this script e.g.:

        python3 local w apikey.xyz
        """
    )
    exit(1)

try:
    read_only = True
    if sys.argv[2] and sys.argv[2] == "w":
        read_only = False
except Exception:
    read_only = True

try:
    API_KEY = sys.argv[3]
except Exception:
    API_KEY = None

if env != "local" and env != "int" and env != "uat":
    exit(
        "Invalid environment variable: {}. Valid options are: local, int, or uat.".format(
            env
        )
    )

with open("config.json") as json_file:
    data = json.load(json_file)
    pools = []
    config = data[env]
    pp.pprint(config)

    base_url = config["api_base_url"]
    print(base_url)
    api_key = config["api_key"]

    # Get the current pools setup
    r = requests.get(
        f"{base_url}/pools",
        headers={"x-api-key": API_KEY if API_KEY else api_key},
    )
    print(r)
    if r.status_code == 200:
        pools = r.json()
        print("Current Pools:")
        pp.pprint(pools)

        if read_only:
            print("Read only set so all done.")
            exit(0)
    elif r.status_code == 404:
        print("No pools.")
    else:
        exit(f"Read pools failed with status {r.status_code}")

    if len(pools):
        for pool in pools:
            pp.pprint(pool)

            # delete the existing entries and recreate them as per the config.json
            r = requests.delete(
                f"{base_url}/pools/{pool['id']}",
                headers={"x-api-key": API_KEY if API_KEY else api_key},
            )

    for pool in config["pools"]:
        pp.pprint({**pool})
        r = requests.post(
            f"{base_url}/pools",
            headers={"x-api-key": API_KEY if API_KEY else api_key},
            json={**pool},
        )
        if r.status_code != 201:
            exit("Create pool failed.")

    r = requests.get(
        f"{base_url}/pools",
        headers={"x-api-key": API_KEY if API_KEY else api_key},
    )
    print(r)
    if r.status_code == 200:
        pools = r.json()
        print("Current Pools:")
        pp.pprint(pools)

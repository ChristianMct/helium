import sys
import signal
import threading
from multiprocessing import Process
import random
import time
from python_on_whales import DockerClient
import subprocess
import json
import copy 
import pathlib


def signal_handler(sig, frame):
    print('Exiting')
    stop_event.set()
    cleanup()
    print("done")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if len(sys.argv) != 2:
    print("Usage: ./%s n_parties" % sys.argv[0])
    sys.exit(1)

n_parties = int(sys.argv[1])

docker = DockerClient()

clients = ["node-%d" % n for n in range(n_parties)]
nodes = ["cloud"] + clients.copy()
online = list()
offline = nodes.copy()

CLOUD_ID = "cloud"
CLOUD_ADDRESS = "cloud:40000"

MEAN_FAILURES_PER_MIN = 10
MEAN_FAILURE_DURATION_MIN = 10/60

SHAPE_NETWORK = True
NET_BANDWIDTH_LIMIT = "50mbit"
NET_DELAY = "30ms"

SESS_PARAMS = {
    #"ID": "node-0",
    "TLSConfig": {
        "InsecureChannels": True
    },
    "SessionParameters": [{
        "ID": "test-session",
        "RLWEParams": {"LogN":13,"Q":[18014398508400641,18014398510645249,18014398510661633],"P":[36028797018652673], "NTTFlag": True},
        #"Nodes": ["node-0", "node-1",  "node-2"],
		"PublicSeed": "bGF0dGlnMA=="
    }],
    "ObjectStoreConfig": {
        "BackendName": "hybrid",
        "DBPath": "./data/db"            
    },
    "SignatureParameters": {"Type": 1}
}

SETUP_DESC = {
	"Cpk": [
		# "node-0",
		# "node-1",
		# "node-2"
	],
	"GaloisKeys": [
		{ "GaloisEl": 5,"Receivers": ["cloud"]},
		{ "GaloisEl": 25,"Receivers": ["cloud"]},
		{ "GaloisEl": 625,"Receivers": ["cloud"]},
		{ "GaloisEl": 13793,"Receivers": ["cloud"]},
		{ "GaloisEl": 12225,"Receivers": ["cloud"]},
		{ "GaloisEl": 12161,"Receivers": ["cloud"]},
		{ "GaloisEl": 7937,"Receivers": ["cloud"]},
		{ "GaloisEl": 15873,"Receivers": ["cloud"]},
		{ "GaloisEl": 15361,"Receivers": ["cloud"]},
		{ "GaloisEl": 14337,"Receivers": ["cloud"]},
		{ "GaloisEl": 12289,"Receivers": ["cloud"]},
		{ "GaloisEl": 8193,"Receivers": ["cloud"]},
		{ "GaloisEl": 16383,"Receivers": ["cloud"]}
	]
}

CIRCUIT_NAME = "psi"

COMPUTE_DESC = {
     "CircuitName": "psi-2"
}



def time_offline():
    return random.expovariate(MEAN_FAILURE_DURATION_MIN)

def next_failure():
    time.sleep(random.expovariate(MEAN_FAILURES_PER_MIN/60))

def create_setup():
    nodelist = [{"NodeID": node}  for node in nodes]
    nodelist.append({"NodeID": CLOUD_ID, "NodeAddress": CLOUD_ADDRESS})
    with open('nodelist.json', 'w') as outfile:
            json.dump(nodelist, outfile, indent=1)
    
    setupdesc = copy.deepcopy(SETUP_DESC)
    setupdesc["Cpk"] = nodes
    with open('setupdesc.json', 'w') as outfile:
            json.dump(setupdesc, outfile, indent=1)

    computedesc = copy.deepcopy(COMPUTE_DESC)
    computedesc["CircuitName"] = "%s-%d" % (CIRCUIT_NAME, n_parties)
    with open('computedesc.json', 'w') as outfile:
            json.dump(computedesc, outfile, indent=1)
    
    for node in nodes:
        conf = copy.deepcopy(SESS_PARAMS)
        conf["ID"] = node
        conf["SessionParameters"][0]["Nodes"] = list(clients)
        if node == "cloud":
             conf["Address"] = CLOUD_ADDRESS
        with open('%s.json' % node, 'w') as outfile:
            json.dump(conf, outfile, indent=1)


def create_containers():
    docker.remove(nodes, force=True)
    docker.network.remove("exp-net")
    netw = docker.network.create("exp-net")
    for node in nodes:
        entrypoint = "/helium/node"
        command = ["-docompute=false", "-keepRunning=true"]
        env = dict()
        caps = []
        if node != CLOUD_ID and SHAPE_NETWORK:
            entrypoint = "/helium/shape_egress_and_start.sh"
            env = {"RATE_LIMIT" : NET_BANDWIDTH_LIMIT, "DELAY" : NET_DELAY}
            caps = ["NET_ADMIN"]
        docker.create(
            image="heliummpc/helium:latest",
            name=node,
            entrypoint=entrypoint,
            command=command,
            envs=env,
            volumes=[
                (pathlib.Path("./%s.json" % node).absolute(), "/helium/config/node.json"),
                (pathlib.Path("./nodelist.json").absolute(), "/helium/config/nodelist.json"),
                (pathlib.Path("./setupdesc.json").absolute(), "/helium/config/setup.json"),
                (pathlib.Path("./computedesc.json").absolute(), "/helium/config/compute.json"),
            ],
            cap_add=caps,
            networks=[netw],
        )

def stop_clients():
     docker.stop(nodes)

def cleanup():
    for t in timers.values():
         t.cancel()
    docker.remove(nodes, force=True)


def set_online_client(node):
    timers.pop(node, None)
    offline.remove(node)
    docker.start(node)
    online.append(node)
    # runs the ingress traffic shaper
    # subprocess.call(["bash", "./shape_ingress_traffic.sh", node, NET_BANDWIDTH_LIMIT, NET_DELAY])
    print("%s is now online" % node)

def set_online_cloud():
    docker.start(CLOUD_ID, attach=True)
    print("%s is now online" % CLOUD_ID)

timers = dict()

def set_offline(node):
    online.remove(node)
    try:
        docker.kill(node)
    except:
         print("could not kill %s" % node)
    offline.append(node)
    print("%s is now offline" % node)
    t = threading.Timer(time_offline(), set_online_client, [node])
    timers[node] = t
    t.start()
    

def failure_process():
    while True:
        next_failure()
        if stop_event.is_set():
            break
        if len(online) == 0:
            continue # all nodes are already in offline state
        crashed = random.choice(online)
        set_offline(crashed)


if __name__ == '__main__':
    create_setup()

    print("Creating the containers: %s" % nodes)
    create_containers()
    stop_event = threading.Event()
    t = Process(target=failure_process)
    print("Starting up containers...")
    c = Process(target=set_online_cloud)
    c.start()
    for node in clients:
        #set_online_client(node)
        p = Process(target=set_online_client, args=[node])
        p.start()
    #t.start()
    signal.pause()
    #t.join()
    c.join()
    stop_clients()
    #cleanup()

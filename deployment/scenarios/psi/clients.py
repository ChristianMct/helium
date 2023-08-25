import sys
import signal
import threading
from multiprocessing import Process, Manager
import random
import time
from python_on_whales import DockerClient
import subprocess
import json
import copy 
import pathlib
import argparse


HELIUM_PORT = 40000

CLOUD_ID = "cloud"
CLOUD_ADDRESS = "iccluster045.iccluster.epfl.ch:%s" % HELIUM_PORT

SKIP_FAILURES = False
MEAN_FAILURES_PER_MIN = 20
MEAN_FAILURE_DURATION_SEC = 5

SHAPE_NETWORK = True
SHAPE_INGRESS = True
NET_BANDWIDTH_LIMIT = "10mbit"
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
    return random.expovariate(1/MEAN_FAILURE_DURATION_SEC)

def next_failure():
    time.sleep(random.expovariate(MEAN_FAILURES_PER_MIN/60))

def create_setup():
    nodelist = [{"NodeID": node}  for node in nodes]
    nodelist.append({"NodeID": CLOUD_ID, "NodeAddress": CLOUD_ADDRESS})
    with open('nodelist.json', 'w') as outfile:
            json.dump(nodelist, outfile, indent=1)
    
    setupdesc = copy.deepcopy(SETUP_DESC)
    setupdesc["Cpk"] = nodes
    # for gk in setupdesc["GaloisKeys"]:
    #      gk["Receivers"] = nodes
    with open('setupdesc.json', 'w') as outfile:
            json.dump(setupdesc, outfile, indent=1)

    computedesc = copy.deepcopy(COMPUTE_DESC)
    computedesc["CircuitName"] = "%s-%d" % (CIRCUIT_NAME, args.n_parties)
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


def create_containers(containers):
    docker.remove(containers, force=True)
    try:
        docker.network.remove("helium")
    except:
         pass
    client_net = docker.network.create("helium")
    for node in containers:
        entrypoint = "/helium/node"
        command = ["-docompute=false", "-keepRunning=true"]
        env = dict()
        caps = []
        net = "host" if node == "cloud" else client_net
        ports = [(HELIUM_PORT, HELIUM_PORT)] if node == "cloud" else  []

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
            publish=ports,
            cap_add=caps,
            networks=[net],
        )

def stop_all(containers):
     docker.stop(list(containers))

def cancel_online_timers():
     for t in timers.values():
         t.cancel()

def cleanup():
    cancel_online_timers()
    docker.remove(nodes, force=True)


def set_online_client(client):
    timers.pop(client, None)
    offline_clients.remove(client)
    docker.start(client)
    online_clients.append(client)

    #runs the ingress traffic shaper
    if SHAPE_INGRESS and subprocess.call(
         ["bash", "../../apps/shape_ingress_traffic.sh", client, NET_BANDWIDTH_LIMIT, NET_DELAY],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT) != 0:
         print("failed to shape ingress traffic for node %s", client)
         sys.exit(1)

    print("[on=%d, off=%d] %s is now online" % (len(online_clients),len(offline_clients),client))

def set_online_cloud(attach):
    print("%s is now online" % CLOUD_ID)
    docker.start(CLOUD_ID, attach=attach)

def set_offline(client):
    online_clients.remove(client)
    try:
        docker.kill(client)
    except:
         print("could not kill %s" % client)
    offline_clients.append(client)
    toff = time_offline()
    print("[on=%d, off=%d] %s is now offline for %fs" % (len(online_clients),len(offline_clients),client, toff))
    t = threading.Timer(toff, set_online_client, [client])
    timers[client] = t
    t.start()
    

def failure_process():
    while True:
        next_failure()
        if stop_event.is_set():
            break
        if SKIP_FAILURES:
            print("skipped failure (SKIP_FAILURES == True)")
            continue # all nodes are already in offline state 
        if len(online_clients) == 0:
            print("skipped failure (no node online)")
            continue # all nodes are already in offline state
        crashed = random.choice(online_clients)
        set_offline(crashed)


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Starts the Helium nodes for experiments')
    parser.add_argument('n_parties', type=int,
                        help='the number or parties')
    parser.add_argument('--clients',  action='store_true', help='starts the clients')
    parser.add_argument('--server',  action='store_true', help='starts the cloud')

    args = parser.parse_args()
    print("start with %s clients clients=%s server=%s" % (args.n_parties, args.clients, args.server))

    def signal_handler(sig, frame):
        
        if __name__ == '__main__':
            print('Exiting')
            stop_event.set()
            try:
                fp.kill()
            except:
                 pass
            print("done")

    signal.signal(signal.SIGINT, signal_handler)

    docker = DockerClient()
    manager = Manager()

    clients = ["node-%d" % n for n in range(args.n_parties)]
    nodes = ["cloud"] + clients.copy()
    
    
    online_clients = manager.list()
    offline_clients = manager.list(clients)
    timers = dict()

    create_setup()

    containers = [] + clients if args.clients else [] + ["cloud"] if args.server else []

    if len(containers) == 0:
         print("no container to handle, stopping...")
         sys.exit(0)

    print("Creating the containers: %s" % containers)
    create_containers(containers)

    stop_event = threading.Event()
    fp = Process(target=failure_process)

    if args.server:
        print("Starting up the server...")
        c = Process(target=set_online_cloud, args=[False])
        c.start()
    
    if args.clients:
        print("Starting up the clients...")
        for node in clients:
            #set_online_client(node)
            p = Process(target=set_online_client, args=[node])
            p.start()

    fp.start()
    signal.pause()
    print("waiting on fp to terminate")
    fp.join()
    
    stop_all(containers)
    #cleanup()

import sys
import signal
import threading
import random
import time
from python_on_whales import DockerClient
import subprocess


def signal_handler(sig, frame):
    print('Exiting')
    stop_event.set()
    docker.compose.down()
    print("done")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if len(sys.argv) != 2:
    print("Usage: ./%s dockerfile" % sys.argv[0])
    sys.exit(1)


docker = DockerClient(compose_files=[sys.argv[1]], compose_profiles=["all"])

conf = docker.compose.config()

nodes = [n for n in conf.services if n != "cloud"]
online = list()
offline = nodes.copy()

MEAN_FAILURES_PER_MIN = 10
MEAN_FAILURE_DURATION_MIN = 10/60

NET_BANDWIDTH_LIMIT = "50mbit"
NET_DELAY = "30ms"

nodeToPort = {
    "node-0": 40000,
    "node-1": 40001,
    "node-2": 40002,
}

def time_offline():
    return random.expovariate(MEAN_FAILURE_DURATION_MIN)

def next_failure():
    time.sleep(random.expovariate(MEAN_FAILURES_PER_MIN/60))

def set_online(node):
    offline.remove(node)
    online.append(node)
    docker.compose.start(services=[node])
    subprocess.call(["bash", "./shape_ingress_traffic.sh %s %s %s" % (node, NET_BANDWIDTH_LIMIT, NET_DELAY)])
    docker.execute(container=node, command="iperf3 -c iccluster042 -p %d -R" % nodeToPort[node])
    print("%s is now online" % node)
    

def set_offline(node):
    online.remove(node)
    offline.append(node)
    print("%s is now offline" % node)
    docker.compose.kill(services=[node])
    #docker.compose.stop(services=[node])
    threading.Timer(time_offline(), set_online, [node]).start()

def failure_process():
    while True:
        next_failure()
        if stop_event.is_set():
            break
        if len(online) == 0:
            continue # all nodes are already in offline state
        crashed = random.choice(online)
        set_offline(crashed)

print("Creating the containers: %s" % nodes)
docker.compose.up(services=nodes, start=False)
stop_event = threading.Event()
t = threading.Thread(target=failure_process)
print("Starting up containers...")
for node in nodes:
    set_online(node)
#t.start()
signal.pause()
#t.join()
docker.compose.down()
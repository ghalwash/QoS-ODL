import httplib2
import json
import networkx as nx
import numpy as np
import collectData

port_count = 4
hosts = []
switches = []
routes_short_path =[]
route_ports_db = []
natHost = "host:0e:9f:64:5e:83:97"

controllerIP='127.0.0.1:8181'

h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')

resp, content = h.request('http://' + controllerIP + '/restconf/operational/opendaylight-inventory:nodes',"GET")
allFlowStats = json.loads(content)
flowStats = allFlowStats['nodes']['node']

resp, content = h.request('http://'+controllerIP+'/restconf/operational/network-topology:network-topology/',"GET")
alltopology = json.loads(content)
odlNodes = alltopology['network-topology']['topology'][0]['node']
odlEdges = alltopology['network-topology']['topology'][0]['link']
graph = nx.Graph()
for node in odlNodes:
    if (node['node-id']== natHost):
        # print node['node-id']
        continue
    graph.add_node(node['node-id'])
    if node['node-id'].find("openflow") == 0:
        switches.append(node['node-id'])
for edge in odlEdges:                                 #$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$change here
    if (edge['source']['source-node'] == natHost or edge['destination']['dest-node'] == natHost):
        continue
    e = (edge['source']['source-node'], edge['destination']['dest-node'])
    graph.add_edge(*e,Src=edge['source']['source-tp'],Dst=edge['destination']['dest-tp'])
    if edge['source']['source-node'].find("host") == 0 :
        hosts.append(edge['source']['source-node'])

Count_switches = len(switches)
comon_byte_port_utilization = -1 * np.ones([Count_switches + 1,port_count + 1])


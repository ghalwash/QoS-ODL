import httplib2
import json
import string
import datetime
import time
import numpy as np
import config
import networkx as nx
# import requests
# from requests.auth import HTTPBasicAuth
# import networkx as nx

#######################################################################################################
# get Switch Index flow statistics- for each node query all port statistics
#------------------------------------------------------------------------------------------------------
def getIndex(sw):
    sw_id = int(sw.split(":")[1])
    try:
        port_ID = int(sw.split(":")[2])
    except:
        port_ID = -1
    return sw_id,port_ID
#######################################################################################################
# get Port-Satus array - Bytes switchID vs portID return the tx+rx bytes on each port
#------------------------------------------------------------------------------------------------------
def get_Bytes_PortStats_Matrix():
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    resp, content = h.request('http://'+controllerIP+'/restconf/operational/opendaylight-inventory:nodes', "GET")
    allFlowStats = json.loads(content)
    flowStats = allFlowStats['nodes']['node']
    # write port ID, Pkt rx, Pkt tx, bytes rx, bytes tx, drop tx, drop rx
    Count_switches = len(switches)
    Bytes_port_status = -1 * np.ones([Count_switches + 1, port_count+1])
    Bytes_port_status_rx = -1 * np.ones([Count_switches + 1, port_count+1])
    Bytes_port_status_tx = -1 * np.ones([Count_switches + 1, port_count+1])

    for fs in flowStats:

        for i in range(0, port_count+1, 1):
            index, port = getIndex(fs['node-connector'][i]['id'])
            if port != -1 and port !=5:
                Bytes_port_status_rx[index][port] = int(
                    fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                        'bytes']['received'])
                Bytes_port_status_tx[index][port] = int(
                    fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                        'bytes']['transmitted'])
                Bytes_port_status[index][port] = int(
                    fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                        'bytes']['received'] +
                    fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'bytes']['transmitted'])
    return Bytes_port_status_rx.astype(int), Bytes_port_status_tx.astype(int), Bytes_port_status.astype(int)
#######################################################################################################
# get Port-Status array - packets
#------------------------------------------------------------------------------------------------------
def get_Packets_PortStats_Matrix():
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    resp, content = h.request('http://'+controllerIP+'/restconf/operational/opendaylight-inventory:nodes',"GET")
    allFlowStats = json.loads(content)
    Count_switches = len(switches)
    Packets_port_status = -1 * np.ones([Count_switches + 1, port_count +1 ])
    Packets_port_status_tx = -1 * np.ones([Count_switches + 1, port_count +1 ])
    Packets_port_status_rx = -1 * np.ones([Count_switches + 1, port_count +1 ])

    flowStats = allFlowStats['nodes']['node']
    # write port ID, Pkt rx, Pkt tx, bytes rx, bytes tx, drop tx, drop rx
    for fs in flowStats:
        for i in range(0, port_count +1, 1):
            index, port = getIndex(fs['node-connector'][i]['id'])
            if port != -1:
                Packets_port_status_rx[index][port] = int(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets']['received'])
                Packets_port_status_tx[index][port] = int(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets']['transmitted'])
                Packets_port_status[index][port] = int(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets']['received'] +
                                                                  fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets']['transmitted'])
    return Packets_port_status_rx.astype(int),Packets_port_status_tx.astype(int), Packets_port_status.astype(int)
#######################################################################################################
# get flow statistics- for each node query all port statistics
#------------------------------------------------------------------------------------------------------
def get_flowStates():
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    Port_file = open("port_stat.txt", "w+")
    resp, content = h.request('http://'+controllerIP+'/restconf/operational/opendaylight-inventory:nodes', "GET")
    allFlowStats = json.loads(content)
    flowStats = allFlowStats['nodes']['node']
    Port_file.write("\nSwitch ID \tport ID \tName \t port errs \t Pkts rx \tPkts tx \t bytes rx \t bytes tx \t duration \t drop tx \t drop rx \t time \t time-formated ")
    for fs in flowStats:
        for i in range(0,port_count+1,1):
            Port_file.write("\nSwitch ID = " + fs['id'] + "\tport ID = " + fs['node-connector'][i]['id'] \
                            + "\tName = " + fs['node-connector'][i]['flow-node-inventory:name'] \
                            + "\t port errs = "
                            + str(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'transmit-errors']) \
                            + "\t Pkts rx = "
                            + str(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets'][
                    'received']) \
                            + "\t Pkts tx = "
                            + str(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['packets'][
                    'transmitted']) \
                            + "\t bytes rx = "
                            + str(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['bytes'][
                    'received']) \
                            + "\t bytes tx = "
                            + str(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['bytes'][
                    'transmitted']) \
                            + "\t duration = "
                            + str( fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['duration'][
                    'second']) \
                            + "\t drop tx = "
                            + str( fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'transmit-drops']) \
                            + "\t drop rx = " + str(fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'receive-drops']))
            Port_file.write("\t")
            Port_file.write(str(time.time()))
            Port_file.write("\t")
            Port_file.write(datetime.datetime.now().strftime("%a, %d %B %Y %I:%M:%S"))
            try:
                Port_file.write("\t stp - status= " + str(fs['node-connector'][i]['stp-status-aware-node-connector:status']))
            except:
                pass
            Port_file.write("\n")
    Port_file.close()
#######################################################################################################
# get rule statistics-for each flow entry in a table query all flow statistics
#------------------------------------------------------------------------------------------------------
def getRuleState():
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    rule_file = open("rules.txt", "a+")
    resp, content = h.request('http://'+controllerIP+'/restconf/operational/opendaylight-inventory:nodes', "GET")
    allFlowStats = json.loads(content)
    flowStats = allFlowStats['nodes']['node']
    for fs in flowStats:
        for aFlow in fs['flow-node-inventory:table']:
            if (aFlow['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows'] != 0):
                rule_file.write("\nSwitch ID = " + fs["id"] + "\tactive-flows = " + str(
                    aFlow['opendaylight-flow-table-statistics:flow-table-statistics']['active-flows']) \
                                + "\t packets-matched= " + str(
                    aFlow['opendaylight-flow-table-statistics:flow-table-statistics']['packets-matched']) \
                                + "\t packets-looked-up = " + str(
                    aFlow['opendaylight-flow-table-statistics:flow-table-statistics']['packets-looked-up']))

            try:
                for f in aFlow['flow']:
                    rule_file.write("\n" + str(f['id']) + "\t" + "priority= " + str(f['priority']) + "\t" + \
                                    "packet-count= " + str(
                        f['opendaylight-flow-statistics:flow-statistics']['packet-count']) + "\t" + \
                                    "byte-count= " + str(f['opendaylight-flow-statistics:flow-statistics']['byte-count']))
                    try:
                        rule_file.write(
                            "\tmatch-ethernet-type= " + str(f['match']['ethernet-match']['ethernet-type']['type']))
                    except:
                        pass
                    try:
                        rule_file.write("\tmatch-in-port= " + str(f['match']['in-port']))
                    except:
                        pass
                    try:
                        for action in f['instructions']['instruction'][0]['apply-actions']['action']:
                            rule_file.write("\taction-order =" + str(action['order']) + \
                                            "\t action-max-length= " + str(action['output-action']['max-length']) \
                                            + "\t action-output-node-connector= " + str(
                                action['output-action']['output-node-connector']))
                    except:
                        pass
            except:
                pass
        rule_file.write("\t\t")
        rule_file.write(str(time.time()))
        rule_file.write("\t")
        rule_file.write(datetime.datetime.now().strftime("%a, %d %B %Y %I:%M:%S"))
        rule_file.write("\n")
    rule_file.write("############################################################################\n")

    rule_file.close()
#######################################################################################################
#helper function get-packets for two edge nodes
#------------------------------------------------------------------------------------------------------
def get_packet_count(route_ports,port_matching):
   list =[]
   for r in route_ports:
       if (r[0]==port_matching):
           list.append(r)
   return list
#######################################################################################################
# all routes using diskstra algorithm
# #------------------------------------------------------------------------------------------------------
# def getDijkstraRoutes():
#     x = 0
#     q = 0
#     dijkstra_route_file = open("dijkstra_route_file.txt", "w+")
#     for i in range(0,len(hosts),1):
#         for j in range(0,len(hosts),1):
#             q = i + x     # no need for x as q=i
#             routes_dij.append([])
#             routes_dij[q].append(nx.dijkstra_path(graph, hosts[i], hosts[j]))
#         dijkstra_route_file.write(str(routes_dij[q]))
#         dijkstra_route_file.write(str("\n"))
#     dijkstra_route_file.close()
#######################################################################################################
# all diskstra rout between two hosts
#------------------------------------------------------------------------------------------------------
# def getDijkRoute(graph,Src,Dst):
#     route_dij = nx.dijkstra_path(graph, Src, Dst)
#     return routes_dij
#######################################################################################################
# shorted path for all
#------------------------------------------------------------------------------------------------------
# def getShortestPath(g,Src,Dst):
#     routes = []
#     for m in (nx.all_shortest_paths(graph, source=Src, target=Dst)):
#         routes.append(m)
#     return routes
#
# # # ######################################################################################################
# # # build a URL
# # #------------------------------------------------------------------------------------------------------
# def build_flow_url(nodeID,tableID,flowID):
#     url = "http://"+ controllerIP + "/restconf/config/opendaylight-inventory:nodes/node/"+nodeID+"/table/"+tableID+"/flow/"+flowID
#     return url

# #######################################################################################################
# Delete all flows in a node
#------------------------------------------------------------------------------------------------------
# def delete_all_flows_node(node,tableID):
#     url = "http://"+controllerIP+"/restconf/config/opendaylight-inventory:nodes/node/"+node
#     resp, content = h.request(url, "GET")
#     allFlows = json.loads(content)
#     print '###########'
#     for m in allFlows['node'][0]['flow-node-inventory:table'][0]['flow']:
#         delurl = "http://"+controllerIP+"/restconf/config/opendaylight-inventory:nodes/node/" + node + "/table/" + tableID + "/flow/" + flowID
#         resp, content = h.request(delurl, "DELETE")
#         print resp
# #######################################################################################################
# Delete specific flow specified by nodeid and flowname
#------------------------------------------------------------------------------------------------------
# def delete_spec_flow_node(node, tableID, flowID):
#     delurl = "http://"+controllerIP+"/restconf/config/opendaylight-inventory:nodes/node/"+node+"/table/"+tableID+"/flow/"+flowID
#     resp, content = h.request(delurl, "DELETE")
#     print 'resp %s content %s', resp, content
# #######################################################################################################
# shortest_path.reverse()
# push_path(shortest_path, odlEdges, dstIP, srcIP, baseUrl)
######################################################################################################

#######################################################################################################
# shorted path for all
#------------------------------------------------------------------------------------------------------
# def get_shortest_path():
#     routes_short_path_file = open("routes_short_path_file.txt", "w+")
#     route_ports_db_file = open("route_port_db_file.txt", "w+")
#     v = 0
#     x = 0
#     for i in range(0, len(hosts), 1):
#         for j in range(0, len(hosts), 1):
#             v= i+x
#             routes_short_path.append([])
#             for m in (nx.all_shortest_paths(graph, source=hosts[i], target=hosts[j])):
#                 routes_short_path[v].append(m)
#     for m in range(0, len(routes_short_path), 1):
#         if len(routes_short_path[m]) != 0:
#             for s in range(0, len(routes_short_path[m]), 1):
#                 for x in range(0,len(routes_short_path[m][s])-1,1):
#                     edge = graph.get_edge_data(routes_short_path[m][s][x], routes_short_path[m][s][x+1])
#                     x=list(edge.items())
#                     y = get_packet_count(route_ports_db, x[0][1])
#                     routes_short_path[m][s].append(x[0][1])
#                     routes_short_path[m][s].append(y)
#                     routes_short_path[m][s].append(x[1][1])
#                     z = get_packet_count(route_ports_db, x[1][1])
#                     routes_short_path[m][s].append(z)
#                 routes_short_path_file.write(str(routes_short_path[m][s]))
#                 routes_short_path_file.write(str("\n"))
#     for rt in route_ports_db:
#         route_ports_db_file.write(str(rt))
#         route_ports_db_file.write("\n")
#     routes_short_path_file.close()
#     route_ports_db_file.close()
#######################################################################################################
# all routes -port statistics using diskstra algorithm
#------------------------------------------------------------------------------------------------------
# def getDijkstraPortState():
#     dijkstra_port_file = open("dijkstra_port_file.txt", "w+")
#     for m in range(0, len(routes_dij), 1):
#         if len(routes_dij[m]) != 0:
#             for s in range(0, len(routes_dij[m]), 1):
#                 for x in range(0, len(routes_dij[m][s]) - 1, 1):
#                     edge = graph.get_edge_data(routes_dij[m][s][x], routes_dij[m][s][x + 1])
#                     x = list(edge.items())
#                     y = get_packet_count(route_ports_db, x[0][1])
#                     routes_dij[m][s].append(x[0][1])
#                     routes_dij[m][s].append(y)
#                     routes_dij[m][s].append(x[1][1])
#                     z = get_packet_count(route_ports_db, x[1][1])
#                     routes_dij[m][s].append(z)
#
#                 dijkstra_port_file.write(str(routes_dij[m][s]))
#                 dijkstra_port_file.write(str("\n"))
#######################################################################################################
# get-connection array - links trafic matrix - switch ID & port ID index return the switch connected
#------------------------------------------------------------------------------------------------------
def adjacent_switch_matrix():
    # write port ID, Pkt rx, Pkt tx, bytes rx, bytes tx, drop tx, drop rx
    Count_switches = len(switches)
    Connection_array = -1 * np.ones([Count_switches + 1, port_count+1])

    for s in graph.edges:
        if (str(s[0]).find("host") != 0) and (str(s[1]).find("host") != 0):
            x = graph.get_edge_data(s[0],s[1])
            y = list(x.items())
            sw_1,port_1 = getIndex(y[0][1])
            sw_2,port_2 = getIndex(y[1][1])
            Connection_array[sw_1][port_1]=sw_2
            Connection_array[sw_2][port_2]=sw_1
    return Connection_array.astype(int)
#######################################################################################################
# get-link state matrix
#------------------------------------------------------------------------------------------------------
def getLinkStatMatrix(connectionmatrix,portstat):
    Count_switches = len(switches)
    LinkStatus_Array = -1 * np.ones([Count_switches + 1, Count_switches + 1])
    for s in range(1,Count_switches+1,1):
        for i in range(1,port_count+1,1):
            index_switch_colon = int(connectionmatrix[s][i])
            if index_switch_colon != -1:
                LinkStatus_Array[s][index_switch_colon] = portstat[s][i]
    return LinkStatus_Array.astype(int)
#######################################################################################################
# find edge in a rout
#------------------------------------------------------------------------------------------------------
def find_edge(headNode, tailNode):
    for edge in odlEdges:
        if (edge['source']['source-node'] == headNode) and (edge['destination']['dest-node'] ==tailNode):
            return edge
#######################################################################################################
# get hostID from IP address
#------------------------------------------------------------------------------------------------------
def gethostID_from_IP(IP):
    for node in odlNodes:
        if node['node-id'].find("openflow") != 0:
            if node['host-tracker-service:addresses'][0]['ip'] == IP:
                return node['node-id']
    return -1
#######################################################################################################
# get Mac from hostID
#------------------------------------------------------------------------------------------------------
def getMac_from_host_ID(hostID):
    for node in odlNodes:
        if node['node-id'].find("openflow") != 0:
            if  node['node-id'] == hostID:
                return node['host-tracker-service:addresses'][0]['mac']
    return -1
#######################################################################################################
# get IP from hostID
#------------------------------------------------------------------------------------------------------
def getIP_from_host_ID(hostID):
    for node in odlNodes:
        if node['node-id'].find("openflow") != 0:
            if  node['node-id'] == hostID:
                return node['host-tracker-service:addresses'][0]['ip']
    return -1
#######################################################################################################
#return a matrix of zeros and ones, the colons indicates the switches and the rows indicates port
# a one exists for a edgeport in an edge switch
#------------------------------------------------------------------------------------------------------
def get_edge_Matrix():
    Count_switches = len(switches)
    # print Count_switches
    edge_Switch_port_array = np.zeros([Count_switches + 1, port_count + 1])

    for s in graph.edges:
        if (str(s[0]).find("host") == 0) or (str(s[1]).find("host") == 0):
            x = graph.get_edge_data(s[0], s[1])
            y =list(x.items())
            if (str(y[0][1]).find("host") == 0):
                # print y[1][1]
                s = getIndex(y[1][1])
                edge_Switch_port_array[s[0]][s[1]] = 1

            else:
                # print y[0][1]
                s = getIndex(y[0][1])
                edge_Switch_port_array[s[0]][s[1]] = 1

    return edge_Switch_port_array
#######################################################################################################
# ######################################################################################################
# post the using URL and flow in json
#------------------------------------------------------------------------------------------------------
# def post_dict(url, d):
#     resp, content = h.request(
#         uri = url,
#         method = 'PUT',
#         headers={'Content-Type' : 'application/json'},
#         body=json.dumps(d)
#     )
#     return resp, content

# ######################################################################################################
# build URL for ovsdb query QOS and Queue
#------------------------------------------------------------------------------------------------------
# def build_ovs_url(entry,ID):
#     url = "http://"+controllerIP+"/restconf/config/network-topology:network-topology/topology/ovsdb:1/node/ovsdb:HOST1/"+\
#           entry+"/"+ID+"/"
#     return url
#
#
# # ######################################################################################################
# # Create a new Queue in the configuration MD-SAL.
# #------------------------------------------------------------------------------------------------------
# def post_ovs_Queue():
#     queueID = "QUEUE-1"
#     queuentry="ovsdb:queues"
#     dscpValue = 25
#     url =build_ovs_url(queuentry,queueID)
#     body = {"ovsdb:queues": [{"queue-id": queueID, "dscp": dscpValue,"queues-other-config": [
#                     {"queue-other-config-key": "max-rate", "queue-other-config-value": "3600000"}]}]}
#     resp, content = post_dict(url,body)
#     return resp, content

# ######################################################################################################
# get UUID for a specific queue
#------------------------------------------------------------------------------------------------------
def get_queue_uuid():
    queueID = "QUEUE-1"
    queuentry="ovsdb:queues"
    url = build_ovs_url(queuentry,queueID)
    resp, content = h.request(url, "GET")
# #####################################################################################################
# get UUID for specific QOS
# #------------------------------------------------------------------------------------------------------
# def get_QOS_uuid():
#     QosID = "QOS-1"
#     QOSentry = "ovsdb:qos-entries"
#     url = build_ovs_url(QOSentry, QosID)
#     resp, content = h.request(url, "GET")

# ######################################################################################################
# Create a QoS entry.
# Note that the UUID of the Queue entry, obtained by querying the operational MD-SAL of the Queue entry,
# is specified in the queue-list of the QoS entry.
# # Queue entries may be added to the QoS entry at the creation of the QoS entry, or by a subsequent update to the QoS entry.
# #------------------------------------------------------------------------------------------------------
# def post_ovs_QOS():
#     QosID = "QOS-1"
#     QOSentry = "ovsdb:qos-entries"
#     qosType = "ovsdb:qos-type-linux-htb"
#     queueuuid = get_queue_uuid()
#     url = build_ovs_url(QOSentry, QosID)
#     body = { "ovsdb:qos-entries": [ {"qos-id": QosID, "qos-type": qosType,
#                 "qos-other-config": [{ "other-config-key": "max-rate", "other-config-value": "4400000"}],
#                 "queue-list": [
#                     {"queue-number": "0","queue-uuid": queueuuid}]}]}
#     resp, content = post_dict(url, body)
#     return resp, content
#
# def post_ovs_host_connection(remoteport, remoteip,hostname):
#     body = {"node":[{"node-id":"ovsdb://fattree","ovsdb:connection-info":{"remote-port": remoteport,"remote-ip": remoteip}}]}
#     url ="http://"+controllerIP+"/restconf/config/network-topology:network-topology/topology/ovsdb:1/node/ovsdb:%2F%2Ffattree"
#     resp, content = post_dict(url,body)
#     return resp, content
#
# def get_ovs_port_ID():
#     url ="http://<controller-ip>:8181/restconf/operational/network-topology:network-topology/topology/ovsdb:1/node/" \
#          "ovsdb:HOST1%2Fbridge%2Fbr-test/termination-point/testport/"
#
# def add_QOS_port():
#     bridgeID="s1"
#     portID=get_ovs_port_ID()
#     qosuuid = get_QOS_uuid()
#     url = "http://"+controllerIP+"/restconf/config/network-topology:network-topology/topology/ovsdb:1/node/" \
#           "ovsdb:HOST1%2Fbridge%2F"+bridge_ID+"/termination-point/"+portID+"/"
#     body= { "network-topology:termination-point": [{"ovsdb:name": portID, "tp-id": portID, "qos": qosuuid }]}
#     resp, content = post_dict(url, body)
#     return resp, content
#
# # Add QoS to a Port
# Update the termination point entry to include the UUID of the QoS entry,
# obtained by querying the operational MD-SAL, to associate a QoS entry with a port.


# https://hadoop.apache.org/docs/stable/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html

#######################################################################################################
# main program
#######################################################################################################

port_count = 4
hosts = []
switches = []
routes_dij = []
routes_short_path =[]
route_ports_db = []
controllerIP='127.0.0.1:8181'

port_count = 4
hosts = []
switches = []
routes_short_path =[]
route_ports_db = []

controllerIP='127.0.0.1:8181'

h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')
resp, content = h.request('http://'+controllerIP+'/restconf/operational/network-topology:network-topology/',"GET")
alltopology = json.loads(content)
odlNodes = alltopology['network-topology']['topology'][1]['node']
odlEdges = alltopology['network-topology']['topology'][1]['link']
graph = nx.Graph()
for node in odlNodes:
    if (node['node-id']== "host:c6:7f:50:f3:e3:6e"):
        print node['node-id']
        continue
    graph.add_node(node['node-id'])
    if node['node-id'].find("openflow") == 0:
        switches.append(node['node-id'])
for edge in odlEdges:                                 #$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$change here
    if (edge['source']['source-node'] == "host:c6:7f:50:f3:e3:6e" or edge['destination']['dest-node'] == "host:c6:7f:50:f3:e3:6e"):
        continue
    e = (edge['source']['source-node'], edge['destination']['dest-node'])
    graph.add_edge(*e,Src=edge['source']['source-tp'],Dst=edge['destination']['dest-tp'])
    if edge['source']['source-node'].find("host") == 0 :
        hosts.append(edge['source']['source-node'])


x = 0
# edge_matrix = get_edge_Matrix()
while x< 100:
    x=x+1
    connectionMartix = adjacent_switch_matrix()
    tx_b,rx_b, byte_port_matrix_b = get_Bytes_PortStats_Matrix()
    time.sleep(4)
    tx_a,rx_a, byte_port_matrix_a = get_Bytes_PortStats_Matrix()
    byte_port_utilization = byte_port_matrix_a - byte_port_matrix_b

    linkstatusMatrix_b = getLinkStatMatrix(connectionMartix,byte_port_matrix_b)
    linkstatusMatrix_a = getLinkStatMatrix(connectionMartix,byte_port_matrix_a)
    link_utilization = linkstatusMatrix_a - linkstatusMatrix_b
    config.Bytes_current_Link_utilization = link_utilization
    print link_utilization
    print byte_port_utilization

    Portfile = open("/home/haitham/ODL-python/results/port-stat-matrix.txt", "w+")
    Portfile.write("\nbyte port status\n")
    Portfile.write("time\n")
    Portfile.write(str(byte_port_utilization))

    linkfile = open("/home/haitham/ODL-python/results/link-stat-matrix.txt", "w+")
    linkfile.write("\nlink_stat_matrix\n")
    linkfile.write("time\n")
    linkfile.write(str(link_utilization))

Portfile.close()
linkfile.close()

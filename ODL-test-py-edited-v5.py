import httplib2
import json
import networkx as nx
import datetime
import numpy as np
import difflib
import socket
import time
import sys


# import string
# import commands
# import re

#######################################################################################################
# get Switch Index flow statistics- for each node query all port statistics
# ------------------------------------------------------------------------------------------------------
def getIndex(sw):
    sw_id = int(sw.split(":")[1])
    try:
        port_ID = int(sw.split(":")[2])
    except:
        port_ID = -1
    return sw_id, port_ID
#######################################################################################################
# get Port-Satus array - Bytes switchID vs portID return the tx+rx bytes on such port
# ------------------------------------------------------------------------------------------------------
def get_Bytes_PortStats_Matrix():
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    resp, content = h.request('http://' + controllerIP + '/restconf/operational/opendaylight-inventory:nodes', "GET")
    allFlowStats = json.loads(content)
    flowStats = allFlowStats['nodes']['node']
    # write port ID, Pkt rx, Pkt tx, bytes rx, bytes tx, drop tx, drop rx
    Count_switches = len(switches)
    Bytes_port_status = -1 * np.ones([Count_switches + 1, port_count + 1])
    Bytes_port_status_rx = -1 * np.ones([Count_switches + 1, port_count + 1])
    Bytes_port_status_tx = -1 * np.ones([Count_switches + 1, port_count + 1])

    for fs in flowStats:
        for i in range(0, port_count + 2, 1):
            index, port = getIndex(fs['node-connector'][i]['id'])
            if port != -1 and port != 5:  # port number 5 is the nat port
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
# ------------------------------------------------------------------------------------------------------
def get_Packets_PortStats_Matrix():
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    resp, content = h.request('http://' + controllerIP + '/restconf/operational/opendaylight-inventory:nodes', "GET")
    allFlowStats = json.loads(content)
    Count_switches = len(switches)
    Packets_port_status = -1 * np.ones([Count_switches + 1, port_count + 1])
    Packets_port_status_tx = -1 * np.ones([Count_switches + 1, port_count + 1])
    Packets_port_status_rx = -1 * np.ones([Count_switches + 1, port_count + 1])

    flowStats = allFlowStats['nodes']['node']
    # write port ID, Pkt rx, Pkt tx, bytes rx, bytes tx, drop tx, drop rx
    for fs in flowStats:
        for i in range(0, port_count + 2, 1):
            index, port = getIndex(fs['node-connector'][i]['id'])
            if port != -1 and port != 5:
                Packets_port_status_rx[index][port] = int(
                    fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                        'packets']['received'])
                Packets_port_status_tx[index][port] = int(
                    fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                        'packets']['transmitted'])
                Packets_port_status[index][port] = int(
                    fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                        'packets']['received'] +
                    fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                        'packets']['transmitted'])
    return Packets_port_status_rx.astype(int), Packets_port_status_tx.astype(int), Packets_port_status.astype(int)
#######################################################################################################
# get flow statistics- for each node query all port statistics
# ------------------------------------------------------------------------------------------------------
def get_flowStates():
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    Port_file = open("port_stat.txt", "w+")
    resp, content = h.request('http://' + controllerIP + '/restconf/operational/opendaylight-inventory:nodes', "GET")
    allFlowStats = json.loads(content)
    flowStats = allFlowStats['nodes']['node']
    Port_file.write(
        "\nSwitch ID \tport ID \tName \t port errs \t Pkts rx \tPkts tx \t bytes rx \t bytes tx \t duration \t drop tx \t drop rx \t time \t time-formated ")
    for fs in flowStats:
        for i in range(0, port_count + 1, 1):
            Port_file.write("\nSwitch ID = " + fs['id'] + "\tport ID = " + fs['node-connector'][i]['id'] \
                            + "\tName = " + fs['node-connector'][i]['flow-node-inventory:name'] \
                            + "\t port errs = "
                            + str(
                fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'transmit-errors']) \
                            + "\t Pkts rx = "
                            + str(
                fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'packets'][
                    'received']) \
                            + "\t Pkts tx = "
                            + str(
                fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'packets'][
                    'transmitted']) \
                            + "\t bytes rx = "
                            + str(
                fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['bytes'][
                    'received']) \
                            + "\t bytes tx = "
                            + str(
                fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics']['bytes'][
                    'transmitted']) \
                            + "\t duration = "
                            + str(
                fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'duration'][
                    'second']) \
                            + "\t drop tx = "
                            + str(
                fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'transmit-drops']) \
                            + "\t drop rx = " + str(
                fs['node-connector'][i]['opendaylight-port-statistics:flow-capable-node-connector-statistics'][
                    'receive-drops']))
            Port_file.write("\t")
            Port_file.write(str(time.time()))
            Port_file.write("\t")
            Port_file.write(datetime.datetime.now().strftime("%a, %d %B %Y %I:%M:%S"))
            try:
                Port_file.write(
                    "\t stp - status= " + str(fs['node-connector'][i]['stp-status-aware-node-connector:status']))
            except:
                pass
            Port_file.write("\n")
    Port_file.close()
#######################################################################################################
# get rule statistics-for each flow entry in a table query all flow statistics
# ------------------------------------------------------------------------------------------------------
def getRuleState():
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    rule_file = open("rules.txt", "w+")
    resp, content = h.request('http://' + controllerIP + '/restconf/operational/opendaylight-inventory:nodes', "GET")
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
                                    "byte-count= " + str(
                        f['opendaylight-flow-statistics:flow-statistics']['byte-count']))
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
    rule_file.close()
#######################################################################################################
# helper function get-packets for two edge nodes
# ------------------------------------------------------------------------------------------------------
def get_packet_count(route_ports, port_matching):
    list = []
    for r in route_ports:
        if (r[0] == port_matching):
            list.append(r)
    return list
#######################################################################################################
# all routes using diskstra algorithm
# ------------------------------------------------------------------------------------------------------
def getDijkstraRoutes():
    x = 0
    q = 0
    dijkstra_route_file = open("dijkstra_route_file.txt", "w+")
    for i in range(0, len(hosts), 1):
        for j in range(0, len(hosts), 1):
            q = i + x  # no need for x as q=i
            routes_dij.append([])
            routes_dij[q].append(nx.dijkstra_path(graph, hosts[i], hosts[j]))
        dijkstra_route_file.write(str(routes_dij[q]))
        dijkstra_route_file.write(str("\n"))
    dijkstra_route_file.close()
#######################################################################################################
# all diskstra rout between two hosts
# ------------------------------------------------------------------------------------------------------
def getDijkRoute(graph, Src, Dst):
    route_dij = nx.dijkstra_path(graph, Src, Dst)
    return routes_dij
#######################################################################################################
# shorted path for all
# ------------------------------------------------------------------------------------------------------
def getShortestPath(g, Src, Dst):
    routes = []
    for m in (nx.all_shortest_paths(g, source=Src, target=Dst)):
        routes.append(m)
    return routes
# ######################################################################################################
# push_path to all switches t- takes a path and the edges from the API call and pushes the appropriate
#  flows to the switches.
# ------------------------------------------------------------------------------------------------------

# ######################################################################################################
# calulate path distance and return the two candidates
# ------------------------------------------------------------------------------------------------------
def get_dissimilar_paths(path):
    # canditate1 = path[0]
    # candidate2 = path[2]
    # # print list(set(canditate1).intersection(candidate2))
    # sm = difflib.SequenceMatcher(None, canditate1, candidate2)
    similarity = 1
    # print similarity
    print len(path)
    if type(path[0]) != list:
        return None, None

    for i in range(len(path)):
        for j in range(i + 1, len(path)):
            sm = difflib.SequenceMatcher(None, path[i], path[j])
            if sm.ratio() < similarity:
                similarity = sm.ratio()
                canditate1 = path[i]
                canditate2 = path[j]
    return canditate1, canditate2

# ######################################################################################################
# push_path to all switches t- takes a path and the edges from the API call and pushes the appropriate
#  flows to the switches. based on the src & dst port

def getCaditatePaths(srcIP, dstIP):
    hx1 = gethostID_from_IP(srcIP)
    hx2 = gethostID_from_IP(dstIP)
    path = getShortestPath(graph, hx1, hx2)
    return path

def calculatePathCost(path):
    src_ID =''
    dst_ID =''
    delay = 0
    jitter = 0
    port_utilization = 0

    if len(path)==1:
        return 1
    elif len(path)==2:
        src_ID,port_src = getIndex(path[1])
        core_ID,port = getIndex(path[2])
        dst_ID,port = getIndex(path[3])
    else:
        src_ID, port_src = getIndex(path[1])
        core_ID, port = getIndex(path[3])
        dst_ID, port = getIndex(path[5])

    delay = delay_matrix[src_ID][core_ID]+delay_matrix[dst_ID][core_ID]
    jitter = jitter_matix[src_ID][core_ID]+delay_matrix[dst_ID][core_ID]
    # port_utilization =link status matrix will be considered in the cost funtion

    # max port utilization to be considered


    cost = delay + jitter + port_utilization

# ######################################################################################################
# push_path to all switches t- takes a path and the edges from the API call and pushes the appropriate
#  flows to the switches. based on the src & dst port
# ------------------------------------------------------------------------------------------------------
def getTwoBestPaths(srcIP, dstIP):
    tableID = '0'
    paths = getCaditatePaths(srcIP,dstIP)
    if type(paths[0]) != list:
        best_path = paths[0]
        next_best_path = paths[1]
        best_path_cost = calculatePathCost(paths[0])
        next_best_path_cost = calculatePathCost(paths[1])
        for i in paths:
            temp_cost = calculatePathCost(i)
            if temp_cost < best_path_cost:
                best_path_cost = temp_cost
                next_best_path = best_path
                best_path = i
            elif temp_cost < next_best_path_cost:
                next_best_path_cost = temp_cost
                next_best_path = i
        return best_path, next_best_path
    else:
        return paths,paths

def pushPathOoS(srcIP, dstIP):
    best_path, next_best_path = getTwoBestPaths(srcIP, dstIP)
    if best_path==next_best_path:
        print "only on path found"

    # l = len(path)
    # if l > 1 and mode == 1:
    #     m = path[1]
    # else:
    #     m = path[0]
    # print m
    #
    # for i in range(1, len(m) - 1, 1):
    #     edge_egress = find_edge(m[i], m[i + 1])
    #     port_egress = getIndex(edge_egress['source']['source-tp'])
    #     nodeID = m[i]
    #     edge_ingress = find_edge(m[i - 1], m[i])
    #     port_ingress = getIndex(edge_ingress['destination']['dest-tp'])
    #     newFlow = build_flow_src_dst_IP_portOut('name', port_egress[1], srcIP + '/32', dstIP + '/32', flowID)
    #     revFlow = build_flow_src_dst_IP_portOut('name', port_ingress[1], dstIP + '/32', srcIP + '/32', rvflowID)
    #     # print json.dumps(newFlow, indent =2)
    #     Url = build_flow_url(nodeID, tableID, flowID)
    #     resp, content = post_dict(Url, newFlow)
    #     resp, content = post_dict(Url, revFlow)
# ######################################################################################################
# push_path to all switches t- takes a path and the edges from the API call and pushes the appropriate
#  flows to the switches. based on the src & dst port
# ------------------------------------------------------------------------------------------------------
def load_balance(vip_ip, dstPort, srcIP, dstIP, flowID, rvflowID):
    i = 0
    single_path = 1
    tableID = '0'
    ethTypeIp = 0x800
    ipTypeTcp = 0x6
    ipTypeUdp = 0x11
    hx1 = gethostID_from_IP(srcIP)
    hx2 = gethostID_from_IP(dstIP)
    path = getShortestPath(graph, hx1, hx2)
    path_file = open("path.txt", "a+")

    # get_Flow_Cost(path)
    # for m in path:
    # if ther is only one path or the not distination port specified by the user we install one path
    if type(path[0]) != list or (dstPort == 0):
        path_file.write('Src-IP =' + srcIP + 'to dst-IP = ' + dstIP)
        # print path[0]
        path_file.write(str(path[0]))
        push_path_port(path[0], 0, srcIP, dstIP, str(flowID), str(rvflowID), 10)
    else:
        # get the cadidate paths
        path1, path2 = get_dissimilar_paths(path)
        path_file.write('Src-IP =' + srcIP + 'to dst-IP = ' + dstIP)
        path_file.write(str(path1))
        path_file.write(str(path2))
        print path1
        print path2

        # @@@@'
        # if dst port is -1 distinguish based n the IP addtess, VIP goes to one path and there on the other
        # if dst port is specified push the specified dstination to a path and all other to diffrent path

        if dstPort == -1:
            print '@@@@@@@@@@@@@'
            if vip_ip == 1:
                print 'vip = 1'
                print srcIP
                print path1
                push_path_port(path1, 0, srcIP, dstIP, str(flowID), str(rvflowID), 10)
            else:
                print 'vip = 0'
                print srcIP
                print path2
                push_path_port(path2, 0, srcIP, dstIP, str(flowID), str(rvflowID), 20)
        # if dst port is specified push the specified dstination to a path and all other to diffrent path

        else:
            push_path_port(path1, 0, srcIP, dstIP, str(flowID), str(rvflowID), 10)
            x = flowID + 1000
            y = rvflowID + 1000
            push_path_port(path2, dstPort, srcIP, dstIP, str(x), str(y), 20)
# $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
###########################################
def push_path_port(path, dstPort, srcIP, dstIP, flowID, rvflowID, priority):
    for i in range(1, len(path) - 1, 1):
        edge_egress = find_edge(path[i], path[i + 1])
        port_egress = getIndex(edge_egress['source']['source-tp'])
        nodeID = path[i]
        edge_ingress = find_edge(path[i - 1], path[i])
        port_ingress = getIndex(edge_ingress['destination']['dest-tp'])
        # print port_ingress[1]
        # print nodeID
        # print port_egress[1]
        if dstPort == 0:
            newFlow = build_flow_src_dst_IP_portOut('forward-ip-1', port_egress[1], srcIP + '/32', dstIP + '/32',
                                                    flowID, priority)
            revFlow = build_flow_src_dst_IP_portOut('reverse-ip-1', port_ingress[1], dstIP + '/32', srcIP + '/32',
                                                    rvflowID, priority)
        else:
            newFlow = build_flow_src_dst_port_portOut('foward-port-2', port_egress[1], dstPort, srcIP + '/32',
                                                      dstIP + '/32', flowID, priority)
            revFlow = build_flow_src_dst_port_portOut('reverse-port-2', port_ingress[1], dstPort, dstIP + '/32',
                                                      srcIP + '/32', rvflowID, priority)

        # print json.dumps(newFlow, indent =2)
        print nodeID
        Url = build_flow_url(nodeID, "0", flowID)
        rvUrl = build_flow_url(nodeID, "0", rvflowID)

        resp, content = post_dict(Url, newFlow)
        resp, content = post_dict(rvUrl, revFlow)
# print resp
# print newFlow
# 		s = json.dumps(newFlow,indent=2)
# 		print s
# # ######################################################################################################
# # build a URL
# #------------------------------------------------------------------------------------------------------
def build_flow_url(nodeID, tableID, flowID):
    url = "http://" + controllerIP + "/restconf/config/opendaylight-inventory:nodes/node/" + nodeID + "/table/" + tableID + "/flow/" + flowID
    return url
# ######################################################################################################
# build a json flow, with src & dst IP match and output to a certain port
# ------------------------------------------------------------------------------------------------------
def build_flow_src_dst_IP_portOut(flowName, EgressPort, srcIP, dstIP, flowID, priority):
    newFlow = {
        "flow": {
            "id": flowID,
            "instructions": {
                "instruction": {
                    "order": "0",
                    "apply-actions": {
                        "action": [
                            {"order": "0",
                             "output-action": {"max-length": "65535", "output-node-connector": EgressPort}}
                        ]
                    }
                }
            },
            "flow-name": flowName,

            "match": {
                "ethernet-match": {
                    "ethernet-type": {"type": "2048"}
                },
                "ipv4-source": srcIP,
                "ipv4-destination": dstIP
            },
            "priority": priority,
            "table_id": "0"
        }
    }
    return newFlow
# ######################################################################################################
# build a json flow, with src & dst IP match and output to a certain port
# ------------------------------------------------------------------------------------------------------
def build_flow_src_dst_port_portOut(flowName, EgressPort, dstPort, srcIP, dstIP, flowID, priority):
    newFlow = {"flow":
        {
            "id": flowID,
            "instructions": {
                "instruction": {
                    "order": "0",
                    "apply-actions": {
                        "action": [
                            {"order": "0",
                             "output-action": {"output-node-connector": EgressPort, "max-length": "65535"}}
                        ]
                    }
                }
            },
            "flow-name": flowName,
            "match": {
                "ethernet-match": {
                    "ethernet-type": {"type": "2048"}
                },
                "ipv4-source": srcIP,
                "ipv4-destination": dstIP,
                "tcp-destination-port": dstPort,
                # "udp-source-port": srcPort,
                # "udp-destination-port":dstPort,
            },
            "priority": priority,
            "table_id": "0"
        }
    }
    return newFlow
# ######################################################################################################
# build a json flow, with src & dst IP match and output to a certain port
# ------------------------------------------------------------------------------------------------------
def build_flow_entry1(flowName, IngressPort, EgressPort, node, srcIP, dstIP):
    newFlow = {"id": flowName,
               "instructions": {
                   "instruction": {
                       "order": "0",
                       "apply-actions": {
                           "action": [
                               {"order": "0", "set-dl-dst-action": {"address": "02:42:4a:46:fc:03"}},
                               {"order": "1", "set-nw-dst-action": {"ipv4-address": "192.168.1.3/32"}},
                               {"order": "2", "output-action": {"output-node-connector": "3", "max-length": "65535"}}
                           ]
                       }
                   }
               },
               "flow-name": "test",
               "match": {
                   "ethernet-match": {
                       "ethernet-type": {"type": "2048"}
                   },
                   "ipv4-source": "10.0.0.1/32", "ipv4-destination": "10.0.0.2/32"},
               "priority": "32768",
               "table_id": "0"}

    return newFlow
def build_flow_entry_2():
    newFlow = {
        "strict": "false",
        "flow-name": "FooXf103",
        "id": "258",
        "cookie_mask": "255",
        "cookie": "103",
        "table_id": "2",
        "priority": "2",
        "hard-timeout": "1200",
        "idle-timeout": "3400",
        "installHw": "false",
        "instructions": {
            "instruction": {
                "order": "0",
                "apply-actions": {
                    "action": {
                        "order": "0",
                        "output-action": {
                            "output-node-connector": "1",
                            "max-length": "60"
                        }
                    }
                }
            }
        },
        "match": {
            "ethernet-match": {
                "ethernet-type": {"type": "2048"},
                "ethernet-destination": {"address": "ff:ff:29:01:19:61"},
                "ethernet-source": {"address": "00:00:00:11:23:ae"}},
            "ipv4-source": "17.1.2.3/8",
            "ipv4-destination": "172.168.5.6/16",
            "ip-match": {"ip-protocol": "6", "ip-dscp": "2", "ip-ecn": "2"},
            "tcp-source-port": "25364",
            "tcp-destination-port": "8080"
        }
    }
# ######################################################################################################
# build a json flow, with src & dst IP match and output to a certain port
# ------------------------------------------------------------------------------------------------------
def build_flow_entry_QOS():
    newflow = {
        "flow": {
            "id": "iperf",
            "instructions": {
                "instruction": {
                    "order": "0",
                    "apply-actions": {
                        "action": [
                            {
                                "order": "1",
                                "output-action": {
                                    "output-node-connector": "NORMAL",
                                    "max-length": "65535"
                                }
                            },
                            {
                                "order": "0",
                                "set-queue-action": {"queue-id": "1"}
                            }
                        ]
                    }
                }
            },
            "barrier": "true",
            "flow-name": "iperf",
            "match": {
                "ethernet-match": {
                    "ethernet-type": {"type": "2048"}
                },
                "ipv4-source": "10.0.0.2/32",
                "ipv4-destination": "10.0.0.1/32",
                "ip-match": {"ip-protocol": "6"},
                "tcp-destination-port": "12345"
            },
            "hard-timeout": "0",
            "priority": "32768",
            "table_id": "0",
            "idle-timeout": "0"
        }
    }
# #######################################################################################################
# Delete all flows in a node
# ------------------------------------------------------------------------------------------------------
def delete_all_flows_node(node, tableID):
    url = "http://" + controllerIP + "/restconf/config/opendaylight-inventory:nodes/node/" + node
    resp, content = h.request(url, "GET")
    allFlows = json.loads(content)
    print '###########'
    for m in allFlows['node'][0]['flow-node-inventory:table'][0]['flow']:
        delurl = "http://" + controllerIP + "/restconf/config/opendaylight-inventory:nodes/node/" + node + "/table/" + tableID + "/flow/" + flowID
        resp, content = h.request(delurl, "DELETE")
        print resp
# #######################################################################################################
# Delete specific flow specified by nodeid and flowname
# ------------------------------------------------------------------------------------------------------
def delete_spec_flow_node(node, tableID, flowID):
    delurl = "http://" + controllerIP + "/restconf/config/opendaylight-inventory:nodes/node/" + node + "/table/" + tableID + "/flow/" + flowID
    resp, content = h.request(delurl, "DELETE")
    print 'resp %s content %s', resp, content
# #######################################################################################################
# shortest_path.reverse()
# push_path(shortest_path, odlEdges, dstIP, srcIP, baseUrl)
######################################################################################################

#######################################################################################################
# shorted path for all
# ------------------------------------------------------------------------------------------------------
def get_shortest_path():
    routes_short_path_file = open("routes_short_path_file.txt", "w+")
    route_ports_db_file = open("route_port_db_file.txt", "w+")
    v = 0
    x = 0
    for i in range(0, len(hosts), 1):
        for j in range(0, len(hosts), 1):
            v = i + x
            routes_short_path.append([])
            for m in (nx.all_shortest_paths(graph, source=hosts[i], target=hosts[j])):
                routes_short_path[v].append(m)
    for m in range(0, len(routes_short_path), 1):
        if len(routes_short_path[m]) != 0:
            for s in range(0, len(routes_short_path[m]), 1):
                for x in range(0, len(routes_short_path[m][s]) - 1, 1):
                    edge = graph.get_edge_data(routes_short_path[m][s][x], routes_short_path[m][s][x + 1])
                    x = list(edge.items())
                    y = get_packet_count(route_ports_db, x[0][1])
                    routes_short_path[m][s].append(x[0][1])
                    routes_short_path[m][s].append(y)
                    routes_short_path[m][s].append(x[1][1])
                    z = get_packet_count(route_ports_db, x[1][1])
                    routes_short_path[m][s].append(z)
                routes_short_path_file.write(str(routes_short_path[m][s]))
                routes_short_path_file.write(str("\n"))
    for rt in route_ports_db:
        route_ports_db_file.write(str(rt))
        route_ports_db_file.write("\n")
    routes_short_path_file.close()
    route_ports_db_file.close()
#######################################################################################################
# all routes -port statistics using diskstra algorithm
# ------------------------------------------------------------------------------------------------------
def getDijkstraPortState():
    dijkstra_port_file = open("dijkstra_port_file.txt", "w+")
    for m in range(0, len(routes_dij), 1):
        if len(routes_dij[m]) != 0:
            for s in range(0, len(routes_dij[m]), 1):
                for x in range(0, len(routes_dij[m][s]) - 1, 1):
                    edge = graph.get_edge_data(routes_dij[m][s][x], routes_dij[m][s][x + 1])
                    x = list(edge.items())
                    y = get_packet_count(route_ports_db, x[0][1])
                    routes_dij[m][s].append(x[0][1])
                    routes_dij[m][s].append(y)
                    routes_dij[m][s].append(x[1][1])
                    z = get_packet_count(route_ports_db, x[1][1])
                    routes_dij[m][s].append(z)

                dijkstra_port_file.write(str(routes_dij[m][s]))
                dijkstra_port_file.write(str("\n"))
#######################################################################################################
# get-connection array - links trafic matrix - switch ID & port ID index return the switch connected
# ------------------------------------------------------------------------------------------------------
def adjacent_switch_matrix():
    # write port ID, Pkt rx, Pkt tx, bytes rx, bytes tx, drop tx, drop rx
    Count_switches = len(switches)
    Connection_array = -1 * np.ones([Count_switches + 1, port_count + 1])

    for s in graph.edges:
        if (str(s[0]).find("host") != 0) and (str(s[1]).find("host") != 0):
            x = graph.get_edge_data(s[0], s[1])
            y = list(x.items())
            sw_1, port_1 = getIndex(y[0][1])
            # print y[0][1]
            sw_2, port_2 = getIndex(y[1][1])
            # print y[1][1]
            Connection_array[sw_1][port_1] = sw_2
            Connection_array[sw_2][port_2] = sw_1
            # print 'switch {} -- port {} -- switch {} -- port {}'.format(sw_1,port_1,sw_2,port_2)
    return Connection_array.astype(int)
#######################################################################################################
# get-link state matrix
# ------------------------------------------------------------------------------------------------------
def getLinkStatMatrix(connectionmatrix, portstat):
    Count_switches = len(switches)
    LinkStatus_Array = -1 * np.ones([Count_switches + 1, Count_switches + 1])
    for s in range(1, Count_switches + 1, 1):
        for i in range(1, port_count + 1, 1):
            index_switch_colon = int(connectionmatrix[s][i])
            if index_switch_colon != -1:
                LinkStatus_Array[s][index_switch_colon] = portstat[s][i]
            # print index_switch_colon
            # print 's={} and i={}'.format(s,i)
            # print "**************************"
    return LinkStatus_Array.astype(int)
#######################################################################################################
# find edge in a rout
# ------------------------------------------------------------------------------------------------------
def find_edge(headNode, tailNode):
    for edge in odlEdges:
        if (edge['source']['source-node'] == headNode) and (edge['destination']['dest-node'] == tailNode):
            return edge
#######################################################################################################
# get hostID from IP address
# ------------------------------------------------------------------------------------------------------
def gethostID_from_IP(IP):
    for node in odlNodes:
        if node['node-id'].find("openflow") != 0:
            if node['host-tracker-service:addresses'][0]['ip'] == IP:
                return node['node-id']
    return -1
#######################################################################################################
# get Mac from hostID
# ------------------------------------------------------------------------------------------------------
def getMac_from_host_ID(hostID):
    for node in odlNodes:
        if node['node-id'].find("openflow") != 0:
            if node['node-id'] == hostID:
                return node['host-tracker-service:addresses'][0]['mac']
    return -1
#######################################################################################################
# get IP from hostID
# ------------------------------------------------------------------------------------------------------
def getIP_from_host_ID(hostID):
    for node in odlNodes:
        if node['node-id'].find("openflow") != 0:
            if node['node-id'] == hostID:
                return node['host-tracker-service:addresses'][0]['ip']
    return -1
#######################################################################################################
# return a matrix of zeros and ones, the colons indicates the switches and the rows indicates port
# a one exists for a edgeport in an edge switch
# ------------------------------------------------------------------------------------------------------
def get_edge_Matrix():
    Count_switches = len(switches)
    edge_Switch_port_array = np.zeros([Count_switches + 1, port_count + 1])
    for s in graph.edges:
        if (str(s[0]).find("host") == 0) or (str(s[1]).find("host") == 0):
            x = graph.get_edge_data(s[0], s[1])
            y = list(x.items())
            if (str(y[0][1]).find("host") == 0):
                print y[1][1]
                s = getIndex(y[1][1])
                edge_Switch_port_array[s[0]][s[1]] = 1
            else:
                print y[0][1]
                s = getIndex(y[0][1])
                edge_Switch_port_array[s[0]][s[1]] = 1
    return edge_Switch_port_array
#######################################################################################################
# get flow cost
# ------------------------------------------------------------------------------------------------------
def get_Flow_Cost(path):
    for m in path:

        # print "***********"
        # print m
        # print len(m)
        for i in range(1, len(m) - 2, 1):
            edge = find_edge(m[i], m[i + 1])
        # print 'src= {}  dest= {}'.format(edge['source']['source-tp'], edge['destination']['dest-tp'])
        # print getIndex(edge['source']['source-tp'])
        # print getIndex(edge['destination']['dest-tp'])
    # print type(m)
    # print len(m)
# ######################################################################################################
# post the using URL and flow in json
# ------------------------------------------------------------------------------------------------------
def post_dict(url, d):
    resp, content = h.request(
        uri=url,
        method='PUT',
        headers={'Content-Type': 'application/json'},
        body=json.dumps(d)
    )
    return resp, content
# ######################################################################################################
# build URL for ovsdb query QOS and Queue
# ------------------------------------------------------------------------------------------------------
def build_ovs_url(entry, ID):
    url = "http://" + controllerIP + "/restconf/config/network-topology:network-topology/topology/ovsdb:1/node/ovsdb:HOST1/" + \
          entry + "/" + ID + "/"
    return url
# ######################################################################################################
# Create a new Queue in the configuration MD-SAL.
# ------------------------------------------------------------------------------------------------------
def post_ovs_Queue():
    queueID = "QUEUE-1"
    queuentry = "ovsdb:queues"
    dscpValue = 25
    url = build_ovs_url(queuentry, queueID)
    body = {"ovsdb:queues": [{"queue-id": queueID, "dscp": dscpValue, "queues-other-config": [
        {"queue-other-config-key": "max-rate", "queue-other-config-value": "3600000"}]}]}
    resp, content = post_dict(url, body)
    return resp, content
# ######################################################################################################
# get UUID for a specific queue
# ------------------------------------------------------------------------------------------------------
def get_queue_uuid():
    queueID = "QUEUE-1"
    queuentry = "ovsdb:queues"
    url = build_ovs_url(queuentry, queueID)
    resp, content = h.request(url, "GET")
# #####################################################################################################
# get UUID for specific QOS
# ------------------------------------------------------------------------------------------------------
def get_QOS_uuid():
    QosID = "QOS-1"
    QOSentry = "ovsdb:qos-entries"
    url = build_ovs_url(QOSentry, QosID)
    resp, content = h.request(url, "GET")

# ######################################################################################################
# Create a QoS entry.
# Note that the UUID of the Queue entry, obtained by querying the operational MD-SAL of the Queue entry,
# is specified in the queue-list of the QoS entry.
# Queue entries may be added to the QoS entry at the creation of the QoS entry, or by a subsequent update to the QoS entry.
# ------------------------------------------------------------------------------------------------------
def post_ovs_QOS():
    QosID = "QOS-1"
    QOSentry = "ovsdb:qos-entries"
    qosType = "ovsdb:qos-type-linux-htb"
    queueuuid = get_queue_uuid()
    url = build_ovs_url(QOSentry, QosID)
    body = {"ovsdb:qos-entries": [{"qos-id": QosID, "qos-type": qosType,
                                   "qos-other-config": [
                                       {"other-config-key": "max-rate", "other-config-value": "4400000"}],
                                   "queue-list": [
                                       {"queue-number": "0", "queue-uuid": queueuuid}]}]}
    resp, content = post_dict(url, body)
    return resp, content

def post_ovs_host_connection(remoteport, remoteip, hostname):
    body = {"node": [
        {"node-id": "ovsdb://fattree", "ovsdb:connection-info": {"remote-port": remoteport, "remote-ip": remoteip}}]}
    url = "http://" + controllerIP + "/restconf/config/network-topology:network-topology/topology/ovsdb:1/node/ovsdb:%2F%2Ffattree"
    resp, content = post_dict(url, body)
    return resp, content

def get_ovs_port_ID():
    url = "http://<controller-ip>:8181/restconf/operational/network-topology:network-topology/topology/ovsdb:1/node/" \
          "ovsdb:HOST1%2Fbridge%2Fbr-test/termination-point/testport/"

def add_QOS_port():
    bridgeID = "s1"
    portID = get_ovs_port_ID()
    qosuuid = get_QOS_uuid()
    url = "http://" + controllerIP + "/restconf/config/network-topology:network-topology/topology/ovsdb:1/node/" \
                                     "ovsdb:HOST1%2Fbridge%2F" + bridge_ID + "/termination-point/" + portID + "/"
    body = {"network-topology:termination-point": [{"ovsdb:name": portID, "tp-id": portID, "qos": qosuuid}]}
    resp, content = post_dict(url, body)
    return resp, content

# Add QoS to a Port
# Update the termination point entry to include the UUID of the QoS entry,
# obtained by querying the operational MD-SAL, to associate a QoS entry with a port.

# https://hadoop.apache.org/docs/stable/hadoop-yarn/hadoop-yarn-site/ResourceManagerRest.html
#############################################################################################
# get delay and jitter from hosts, source and destination
#############################################################################################
def get_delay_jitter(srcIP, dstIP):
    hx1 = gethostID_from_IP(srcIP)
    hx2 = gethostID_from_IP(dstIP)
    path = getShortestPath(graph, hx1, hx2)
    case = len(path)
    list_ip_ping = ''
    list_ID_ping = ''
    src_dst_ID = ''
	# case 1: the source and destination are connected to the same edge switch
	# case 2: the source and destination has a path length of two which means that the
	# they are in the same pod
	# other case: the source and the distination are in diffrent pods which means that the are
	# passing by a core switch
    if case == 1:
		print "only one hop"
		print path
		src_sw_id_, port_1 = getIndex(path[0][1])
		mid_sw_id_ = src_sw_id_
		mid_sw_ip_ = '10.0.0.' + str(mid_sw_id_ + 100)
		dst_sw_id_ = src_sw_id_
		list_ip_ping = mid_sw_ip_
		list_ID_ping = str(mid_sw_id_)
		rtt_src = 0
		rtt_dst = 0
		src_dst_ID = src_sw_id_ + ' ' + src_sw_id_
    elif case == 2:
		print "pod level0"
		src_sw_id_ = [0, 0]
		mid_sw_id_ = [0, 0]
		mid_sw_ip_ = ['', '']
		dst_sw_id_ = [0, 0]
		for i in 0, 1:
			print path[i]
			src_sw_id_[i], port_1 = getIndex(path[i][1])
			print src_sw_id_[i]
			mid_sw_id_[i], port_1 = getIndex(path[i][2])
			mid_sw_ip_[i] = '10.0.0.' + str(mid_sw_id_[i] + 100)
			# print '10.0.0.'+str(mid_sw_id_[i])
			dst_sw_id_[i], port_1 = getIndex(path[i][3])
			print dst_sw_id_[i]
			src_dst_ID = str(src_sw_id_[0]) + ' ' + str(dst_sw_id_[0])

		list_ip_ping = mid_sw_ip_[0] + ' ' + mid_sw_ip_[1]
		list_ID_ping = str(mid_sw_id_[0]) + ' ' + str(mid_sw_id_[1])
		print list_ip_ping
		rtt_src, rtt_dst = get_avg_mdev(srcIP, dstIP, list_ip_ping)
    else:
        print "core level"
        src_sw_id_ = [0, 0, 0, 0]
        mid_sw_id_ = [0, 0, 0, 0]
        mid_sw_ip_ = ['', '', '', '']
        dst_sw_id_ = [0, 0, 0, 0]
        for i in 0, 1, 2, 3:
            print path[i]
            src_sw_id_[i], port_1 = getIndex(path[i][1])
            mid_sw_id_[i], port_1 = getIndex(path[i][3])
            mid_sw_ip_[i] = '10.0.0.' + str(mid_sw_id_[i] + 100)
            dst_sw_id_[i], port_1 = getIndex(path[i][5])
        src_dst_ID = str(src_sw_id_[0]) + ' ' + str(dst_sw_id_[0])
        list_ip_ping = mid_sw_ip_[0] + ' ' + mid_sw_ip_[1] + ' ' + mid_sw_ip_[2] + ' ' + mid_sw_ip_[3]
        list_ID_ping = str(mid_sw_id_[0]) + ' ' + str(mid_sw_id_[1]) + ' ' + str(mid_sw_id_[2]) + ' ' + str(
            mid_sw_id_[3])
        rtt_src, rtt_dst = get_avg_mdev(srcIP, dstIP, list_ip_ping)
    return rtt_src, rtt_dst, list_ID_ping, src_dst_ID


def get_avg_mdev(src_host, dst_host, ip_list):
    listenPort = 5000
    s1 = socket.socket()
    s2 = socket.socket()
    print 'get average', ip_list

    print 'Socket created'
    try:
        s1.connect((src_host, listenPort))
        s2.connect((dst_host, listenPort))
    except socket.error as msg:
        print 'Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        sys.exit()
    print 'get average', ip_list
    s1.send(ip_list)
    s2.send(ip_list)
    rtt_src = s1.recv(1024).decode()
    s1.close()
    rtt_dst = s2.recv(1024).decode()
    s2.close()
    return rtt_src, rtt_dst


def update_delay_jitter_matrix(delay_matrix, jitter_matix, rtt_src, rtt_dst, core_list, src_dst_ID):
    # print delay_matrix
    # print jitter_matix
    print core_list
    rtt_src_Items = str(rtt_src).strip().split(' ')
    rtt_dst_Items = str(rtt_dst).strip().split(' ')
    core_list_Items = str(core_list).strip().split(' ')
    src_dst_ID_Items = str(src_dst_ID).strip().split(' ')
    src = int(src_dst_ID_Items[0])
    dst = int(src_dst_ID_Items[1])

    print rtt_src_Items
    print rtt_dst_Items
    print len(rtt_src_Items)

    for i in range(0, len(rtt_src_Items) / 2, 1):
        print '----------delay------------'
        print 'core', core_list_Items[i]
        print 'src', src, '  ', rtt_src_Items[2 * i]
        print 'dst', dst, '  ', rtt_dst_Items[2 * i]

        print '----------jitter-----------'
        print 'core', core_list_Items[i]
        print 'src', src, '  ', rtt_src_Items[2 * i + 1]
        print 'dst', dst, '  ', rtt_dst_Items[2 * i + 1]

        core_delay = int(core_list_Items[i])
        src_sw_delay = float(rtt_src_Items[2 * i])
        dst_sw_delay = float(rtt_dst_Items[2 * i])
        delay_matrix[core_delay][src] = src_sw_delay
        delay_matrix[core_delay][dst] = dst_sw_delay

        print '----------jitter-----------'
        core_jitter = int(core_list_Items[i])
        src_sw_jitter = float(rtt_src_Items[2 * i + 1])
        dst_sw_jitter = float(rtt_dst_Items[2 * i + 1])
        jitter_matix[core_jitter][src] = src_sw_jitter
        jitter_matix[core_jitter][dst] = dst_sw_jitter
    print delay_matrix
    print jitter_matix


#######################################################################################################
# main program
#######################################################################################################
port_count = 4
hosts = []
switches = []
routes_dij = []
routes_short_path = []
route_ports_db = []
controllerIP = '127.0.0.1:8181'
src_IP = '10.0.0.1'  # Symbolic name, meaning all available interfaces
source_agent_HOST_listenPort = 5000
dst_IP = '10.0.0.8'

h = httplib2.Http(".cache")
h.add_credentials('admin', 'admin')
resp, content = h.request('http://' + controllerIP + '/restconf/operational/network-topology:network-topology/', "GET")
alltopology = json.loads(content)
odlNodes = alltopology['network-topology']['topology'][1]['node']
odlEdges = alltopology['network-topology']['topology'][1]['link']
graph = nx.Graph()
for node in odlNodes:
    if (node['node-id'] == "host:c6:7f:50:f3:e3:6e"):  # $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$change here
        print "***************************************"
        print node['node-id']
        print "***************************************"
        continue
    graph.add_node(node['node-id'])
    if node['node-id'].find("openflow") == 0:
        switches.append(node['node-id'])
    # hosts.append(edge['source']['source-node'])
for edge in odlEdges:
    if (edge['source']['source-node'] == "host:c6:7f:50:f3:e3:6e" or edge['destination'][
        'dest-node'] == "host:c6:7f:50:f3:e3:6e"):
        continue
    e = (edge['source']['source-node'], edge['destination']['dest-node'])
    graph.add_edge(*e, Src=edge['source']['source-tp'], Dst=edge['destination']['dest-tp'])
    # find all hosts in the topology
    if edge['source']['source-node'].find("host") == 0:
        hosts.append(edge['source']['source-node'])

# print list(graph.nodes)

Count_switches = len(switches)
Bytes_Link_status_array = -1 * np.ones([Count_switches + 1, Count_switches + 1])
Packets_Link_status_array = -1 * np.ones([Count_switches + 1, Count_switches + 1])
Bytes_Link_status_array = -1 * np.ones([Count_switches + 1, Count_switches + 1])
delay_matrix = -1 * np.ones([Count_switches + 1, Count_switches + 1])
jitter_matix = -1 * np.ones([Count_switches + 1, Count_switches + 1])

# rtt_src, rtt_dst, core_list, src_dst_ID = get_delay_jitter(src_IP, dst_IP)
# print src_dst_ID
# print rtt_dst
# print rtt_src
# print core_list
print config.Bytes_current_Link_utilization


# update_delay_jitter_matrix(delay_matrix, jitter_matix, rtt_src, rtt_dst, core_list, src_dst_ID)

# get_two_best_routes()
# push_path_IP()
# load_balance()
#
# set_best_routes()


############################
# socket communication with the agent host
# get_avg_mdev('10.0.0.1','10.0.0.8')
############################

# Bytes_Switch_port_status_array = get_Bytes_PortStats_Matrix()
# Packets_Switch_port_status_array = get_Packets_PortStats_Matrix()
# Connection_Matrix = adjacent_switch_matrix()
#
# print Bytes_Switch_port_status_array
# print Packets_Switch_port_status_array
# print adjacent_switch_matrix()
#
# print getLinkStatMatrix(Connection_Matrix,Bytes_Switch_port_status_array)

# push_path('10.0.0.9', '10.0.0.13','2',0)
# push_path('10.0.0.9', '10.0.0.14','2',0)
# push_path('10.0.0.9', '10.0.0.15','2',0)
# push_path('10.0.0.9', '10.0.0.16','2',0)

# push_path('10.0.0.13', '10.0.0.9','3',0)
# push_path('10.0.0.14', '10.0.0.9','3',0)
# push_path('10.0.0.15', '10.0.0.9','3',0)
# push_path('10.0.0.16', '10.0.0.9','3',0)
#

# load_balance(0,-1,'10.0.0.1', '10.0.0.5',15,51)
# load_balance(0,-1,'10.0.0.1', '10.0.0.6',16,61)
# load_balance(0,-1,'10.0.0.1', '10.0.0.7',17,71)
# load_balance(0,-1,'10.0.0.1', '10.0.0.8',18,81)

# load_balance(0,0,'10.0.0.1', '10.0.0.5',15,51)
# load_balance(0,0,'10.0.0.1', '10.0.0.6',16,61)
# load_balance(0,0,'10.0.0.1', '10.0.0.7',17,71)
# load_balance(0,0,'10.0.0.1', '10.0.0.8',18,81)
# #
# #
# load_balance(0,0,'10.0.0.9', '10.0.0.10',910,109)
# load_balance(0,0,'10.0.0.9', '10.0.0.11',911,119)
# load_balance(0,0,'10.0.0.9', '10.0.0.12',912,129)
# load_balance(0,0,'10.0.0.9', '10.0.0.13',913,139)
# load_balance(0,0,'10.0.0.9', '10.0.0.14',914,149)
# load_balance(0,0,'10.0.0.9', '10.0.0.15',915,159)
# load_balance(0,0,'10.0.0.9', '10.0.0.16',916,169)
#
# load_balance(0,0,'10.0.0.10', '10.0.0.11',910,109)
# load_balance(0,0,'10.0.0.10', '10.0.0.12',910,109)
# load_balance(0,0,'10.0.0.10', '10.0.0.13',910,109)
# load_balance(0,0,'10.0.0.10', '10.0.0.14',910,109)
# load_balance(0,0,'10.0.0.10', '10.0.0.15',910,109)
# load_balance(0,0,'10.0.0.10', '10.0.0.16',910,109)
#
# load_balance(0,0,'10.0.0.11', '10.0.0.12',910,109)
# load_balance(0,0,'10.0.0.11', '10.0.0.13',910,109)
# load_balance(0,0,'10.0.0.11', '10.0.0.14',910,109)
# load_balance(0,0,'10.0.0.11', '10.0.0.15',910,109)
# load_balance(0,0,'10.0.0.11', '10.0.0.16',910,109)
#
# load_balance(0,0,'10.0.0.12', '10.0.0.13',910,109)
# load_balance(0,0,'10.0.0.12', '10.0.0.14',910,109)
# load_balance(0,0,'10.0.0.12', '10.0.0.15',910,109)
# load_balance(0,0,'10.0.0.12', '10.0.0.16',910,109)
#
# load_balance(0,0,'10.0.0.13', '10.0.0.14',910,109)
# load_balance(0,0,'10.0.0.13', '10.0.0.15',910,109)
# load_balance(0,0,'10.0.0.13', '10.0.0.16',910,109)
#
# load_balance(0,0,'10.0.0.14', '10.0.0.15',910,109)
# load_balance(0,0,'10.0.0.14', '10.0.0.16',910,109)
# load_balance(0,0,'10.0.0.15', '10.0.0.16',910,109)

#
# load_balance(0,-1,'10.0.0.9', '10.0.0.10',910,109)
# load_balance(0,-1,'10.0.0.9', '10.0.0.11',911,119)
# load_balance(0,-1,'10.0.0.9', '10.0.0.12',912,129)
# load_balance(0,-1,'10.0.0.9', '10.0.0.13',913,139)
# load_balance(1,-1,'10.0.0.9', '10.0.0.14',914,149)
# load_balance(1,-1,'10.0.0.9', '10.0.0.15',915,159)
# load_balance(1,-1,'10.0.0.9', '10.0.0.16',916,169)

# load_balance(0,'10.0.0.11', '10.0.0.12',1112,1211)
# load_balance(0,'10.0.0.11', '10.0.0.13',1113,1311)
# load_balance(0,'10.0.0.11', '10.0.0.14',1114,1411)
# load_balance(0,'10.0.0.11', '10.0.0.15',1115,1511)
# load_balance(0,'10.0.0.11', '10.0.0.16',1116,1611)
# load_balance(0,'10.0.0.12', '10.0.0.13',1213,1312)
# load_balance(0,'10.0.0.12', '10.0.0.14',1214,1412)
# load_balance(0,'10.0.0.12', '10.0.0.15',1215,1512)
# load_balance(0,'10.0.0.12', '10.0.0.16',1216,1612)
# load_balance(0,'10.0.0.13', '10.0.0.14',1314,1413)
# load_balance(0,'10.0.0.13', '10.0.0.15',1315,1513)
# load_balance(0,'10.0.0.13', '10.0.0.16',1316,1613)
# load_balance(0,'10.0.0.14', '10.0.0.15',1415,1514)
# load_balance(0,'10.0.0.14', '10.0.0.16',1416,1614)
# load_balance(0,'10.0.0.15', '10.0.0.16',1516,1615)

# edgePortBW = PortBW * get_edge_Matrix()
#
# Portfile.write(str(edgePortBW))
#
# Portfile.close()
# s = adjacent_switch_matrix()
# print getLinkStatMatrix(s,total)

# monitor = interfaces of edge switches that are connected to hosts
# trigger an event when the interface shows high rate of input packets
# for the hadoop nodes, you need to alocate high bandwidth based on the inputed bytes
# for the tx and rx form the edge switch you can decide the traffic matrix of bytes into the network and out of the network
# we need to find two paths that are disjoint as much as possible
# I need a method to automatically analyzie new packet arriving and protocols running in the network
# IDataPacketService
# http://www.cse.scu.edu/~mwang2/projects/L2_learningOpenDaylight_14f.pdf

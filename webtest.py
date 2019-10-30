import websocket
import xml.etree.ElementTree as ET
from threading import Thread
import httplib2
import json

class WebSockettest:
    port_count = 4
    controllerIP = '127.0.0.1:8181'
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    def __init__(self):
        threads = []
        ws = []
        port_count = 4
        connect = []
        #    connectors = [(node,port,address-tracker_id) , .....]
        connectors = [("7", "3", "1"), ("20", "3", "0")]
        # while (1):
        for node, port, trackid, ip in connect:
            print node
            print port
            print trackid
            x = "ws://localhost:8185/data-change-event-subscription/opendaylight-inventory:nodes/opendaylight-inventory:node/openflow%3A" + node + "/opendaylight-inventory:node-connector/openflow%3A" + node + "%3A" + port + "/address-tracker:addresses/" + trackid + "/address-tracker:last-seen/datastore=OPERATIONAL/scope=SUBTREE"
            ws.append(x)

        websocket.enableTrace(True)

        for w in ws:
            print w
            worker = Thread(target=monitor, args=(w,))
            threads.append(worker)
            worker.setDaemon(True)
            worker.start()
        #     # print "pinging ip =", i
        #
        # # wait until worker threads are done to exit
        for x in threads:
            x.join()
        #
        # ws1 = websocket.WebSocketApp(on_message = on_message,
        #                       on_error = on_error,
        #                       on_close = on_close)
        #
        # ws.run_forever()
        # ws1.run_forever()

    def getIndex(sw):
        sw_id = int(sw.split(":")[1])
        try:
            port_ID = int(sw.split(":")[2])
        except:
            port_ID = -1
        return sw_id,port_ID

    def create_data_change_event_subscription(d):
        h = httplib2.Http(".cache")
        h.add_credentials('admin', 'admin')
        resp, content = h.request(
            uri='http://localhost:8181/restconf/operations/sal-remote:create-data-change-event-subscription',
            method='post',
            headers={'Content-Type': 'application/json'},
            body=json.dumps(d)
        )
        return resp, content
    def get_address_tracker():
        h = httplib2.Http(".cache")
        h.add_credentials('admin', 'admin')
        resp, content = h.request('http://'+controllerIP+'/restconf/operational/opendaylight-inventory:nodes', "GET")
        allFlowStats = json.loads(content)
        flowStats = allFlowStats['nodes']['node']
        for fs in flowStats:
            for i in range(0, port_count+1, 1):
                index, port = self.getIndex(fs['node-connector'][i]['id'])
                if port != -1 and port !=5:
                    try:
                        id = str(fs['node-connector'][i]['address-tracker:addresses'][0]['id'])
                        ip = str(fs['node-connector'][i]['address-tracker:addresses'][0]['ip'])
                        port_id = str(port)
                        node_id = str(index)
                        # print node_id , port_id, id , ip
                        connect.append((node_id , port_id, id , ip))
                    except:
                        pass

        print(connect)

    def on_message(ws, message):
        # print(message)
        websocketfile.write(str(message))
        print "*********************************************"
        # print message
        elem = ET.fromstring(message)
        # print elem
        for e in elem.iter():
            # print e
            if e.tag == '{urn:ietf:params:xml:ns:netconf:notification:1.0}eventTime' or e.tag == '{urn:opendaylight:params:xml:ns:yang:controller:md:sal:remote}path':
                txt = e.text
                start = txt.find("connector[opendaylight-inventory:id='")
                end = txt.find("']/address")
                mySubString = txt[start+37:end]
                if start == -1:
                    print 'time', e.text
                else:
                    print mySubString
                # print e
                print("---------------------------")
        # print elem.findall()    # for elem in reversed(list(tree)):
        #     print elem

        # print doc.getiterator()
        # for parent in doc.getiterator():
        #
        #     print( parent)

        # for parent in doc.getiterator():
        #     for child in parent.findall('addresses'):
        #            parent.remove(child)
        # print (xee.tostring(message))

    def on_error(ws, error):
        print(error)

    def on_close(ws):
        print("### closed ###")

    # def on_open(ws):
    #     def run(*args):
    #         for i in range(3):
    #             time.sleep(1)
    #             ws.send("Hello %d" % i)
    #         time.sleep(1)
    #         ws.close()
    #         print("thread terminating...")
    #     thread.start_new_thread(run, ())
    def monitor(w):
        ws = websocket.WebSocketApp(w, on_message = this.on_message, on_error = this.on_error, on_close = this.on_close)
        ws.run_forever()

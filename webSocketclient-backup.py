import websocket
import xml.etree.ElementTree as ET
from threading import Thread
import threading
import httplib2
import json
import Queue

websocketfile = open("/home/haitham/ODL-python/results/websocket.txt", "w+")
# https://docs.python.org/2/library/xml.etree.elementtree.html
class WebSockettracker:
    port_count = 4
    controllerIP = '127.0.0.1:8181'
    h = httplib2.Http(".cache")
    h.add_credentials('admin', 'admin')
    threads = []
    ws = []
    addresstracks = []
    stream = []
    message_info_status = {}
    average_byte_change = {}
    lock = threading.Lock()
    HistoryEvents = open("history.txt", "w+")
    averageEvents = open("average.txt", "w+")
    events = Queue.Queue()
    node = 1
    port = 1

    def __init__(self):
        # get all listed nodes in the address tracker node inventory data base
        # self.get_address_tracker()
        # get stream URLs by invoking create-data-change-event-subscription
        self.get_stream_url()
        # create the list of web sockets that need to be listened to
        self.get_web_socket_url()
        self.start_listening()

    def get_web_socket_url(self):
        for s_item in self.stream:
            resp, content = self.h.request('http://' + self.controllerIP + '/restconf/streams/stream/'+s_item, "GET")
            start = content.find("location\":\"")
            end = content.find("\"}")
            path = content[start + 11:end]
            self.ws.append(path)
        # print self.ws

    def start_listening(self):
        websocket.enableTrace(True)
        for ws_url in self.ws:
            worker = Thread(target=self.listen, args=(ws_url,))
            self.threads.append(worker)
            worker.setDaemon(True)
            worker.start()
        for x in self.threads:
            x.join()

    def getIndex(self,sw):
        sw_id = int(sw.split(":")[1])
        try:
            port_ID = int(sw.split(":")[2])
        except:
            port_ID = -1
        return sw_id,port_ID

    def create_data_change_event_subscription(self,d):
        h = httplib2.Http(".cache")
        h.add_credentials('admin', 'admin')
        print d
        resp, content = self.h.request(
            uri='http://localhost:8181/restconf/operations/sal-remote:create-data-change-event-subscription',
            method='post',
            headers={'Content-Type': 'application/json'},
            body=json.dumps(d)
        )
        return resp, content

    def get_stream_url(self):
        # for node,port,id,ip in self.addresstracks:
        resp, content = self.create_data_change_event_subscription(self.build_event_subscription_body(self.node,self.port,id))
        print content
        start = content.find("stream-name\":\"")
        end = content.find("\"}}")
        path = content[start + 14:end]
        self.stream.append(path)
        # print self.stream

    def build_event_subscription_body(self, node, port, address_id):
        body = {
            "input": {
                "path": "/opendaylight-inventory:nodes/opendaylight-inventory:node[opendaylight-inventory:id='openflow:7']/flow-node-inventory:table[flow-node-inventory:id='0']",
                "sal-remote-augment:datastore": "OPERATIONAL",
                "sal-remote-augment:scope": "SUBTREE"
            }
        }
        # body = { "input": {
        #     "path": "/opendaylight-inventory:nodes/opendaylight-inventory:node[opendaylight-inventory:id='openflow:"+node+"']/opendaylight-inventory:node-connector[opendaylight-inventory:id='openflow:"+node+":"+port+"']/address-tracker:addresses[address-tracker:id='"+address_id+"']/last-seen",
        #     "sal-remote-augment:datastore": "OPERATIONAL",
        #     "sal-remote-augment:scope": "SUBTREE"
        #     }
        # }
        return body

    def get_address_tracker(self):
        resp, content = self.h.request('http://'+self.controllerIP+'/restconf/operational/opendaylight-inventory:nodes', "GET")
        allFlowStats = json.loads(content)
        flowStats = allFlowStats['nodes']['node']
        for fs in flowStats:
            for i in range(0, self.port_count+1, 1):
                index, port = self.getIndex(fs['node-connector'][i]['id'])
                if port != -1 and port !=5:
                    try:
                        id = str(fs['node-connector'][i]['address-tracker:addresses'][0]['id'])
                        ip = str(fs['node-connector'][i]['address-tracker:addresses'][0]['ip'])
                        port_id = str(port)
                        node_id = str(index)
                        # print node_id , port_id, id , ip
                        self.addresstracks.append((node_id , port_id, id , ip))
                    except:
                        pass
        # print(self.addresstracks)

    def on_message(self,ws, message):
        # print(message)
        time =''
        port_id = ''
        byte_tx = 0
        byte_rx = 0
        time_str=''
        mytime=0

        websocketfile.write(str(message))
        # print "*********************************************"
        print message
        elem = ET.fromstring(message)
        # print elem
        print message
        for e in elem.iter():
            print e
            if e.tag == '{urn:opendaylight:params:xml:ns:yang:controller:md:sal:remote}path':
                txt = e.text
                if txt == '':
                    continue
                start = txt.find("connector[opendaylight-inventory:id='")
                end = txt.find("']/opendaylight-port-statistics")
                mySubString = txt[start+37:end]
                port_id = mySubString
            elif e.tag == '{urn:ietf:params:xml:ns:netconf:notification:1.0}eventTime':
                time = e.text
                time_str = time[time.find("T")+1:len(time)-6]
                h, m, s = time_str.split(':')
                mytime = float(h) * 3600 + float(m) * 60 + float(s)
            elif e.tag == '{urn:opendaylight:port:statistics}received':
                byte_rx = int(e.text)
            elif e.tag == '{urn:opendaylight:port:statistics}transmitted':
                byte_tx = int(e.text)
                # print e
                # print("---------------------------")
        self.lock.acquire()
        try:
            # print self.average_byte_change
            # print self.message_info_status
            # print port_id
            # print self.message_info_status[port_id]
            # print mytime
            # print self.message_info_status[port_id][1]


            dtime = mytime - self.message_info_status[port_id][1]
            # print dtime

            dbyte_rx = round(byte_rx - self.message_info_status[port_id][2],2)
            dbyte_tx = round(byte_tx - self.message_info_status[port_id][3],2)

            average_rx = round(dbyte_rx/dtime,2)
            average_tx = round(dbyte_tx/dtime,2)
            average_traffic = round((dbyte_rx+dbyte_tx)/dtime,2)
            if average_traffic > 30 and (average_tx != 0.0 and average_rx != 0.0):
                self.events.put({port_id: [time_str, average_traffic, average_rx, average_tx]})
                self.average_byte_change.update({port_id:[time_str,average_traffic, average_rx, average_tx]})
                print self.average_byte_change

            # self.lock.acquire()
            self.averageEvents.write("---------------------------------")

            self.averageEvents.write(str(self.average_byte_change))
            # self.lock.release()
        except:
            print "pass"
            pass
        self.averageEvents.write(str(self.average_byte_change))
        self.message_info_status.update({port_id:[time_str,mytime,byte_rx,byte_tx]})
        self.HistoryEvents.write(str(self.message_info_status))
        self.lock.release()



    def on_error(self, ws, error):
        print(error)

    def on_close(self, ws):
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
    def listen(self,ws_url):
        ws = websocket.WebSocketApp(ws_url, on_message = self.on_message, on_error = self.on_error, on_close = self.on_close)
        ws.run_forever()

#--------------------------------------------------------------------------
# main program
#--------------------------------------------------------------------------

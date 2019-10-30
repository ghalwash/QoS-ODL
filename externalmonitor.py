import collectData
import datetime

Portfile = open("/home/haitham/PycharmProjects/QoS/port-utilization-matrix.txt", "w+")
Trafficfile = open("/home/haitham/PycharmProjects/QoS/traffic-utilization-matrix.txt", "w+")

# linkfile = open("/home/haitham/ODL-python/results/link-utilization-matrix.txt", "w+")
c = collectData.DataCollector()

while 1:
    print ("collectData")
    c.update_metric_Matrices()

package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/signalsciences/ipv4"
)

type connection struct {
	sip   uint32
	dip   uint32
	sport uint16
	dport uint16
}

var (
	newConnectionsCount = promauto.NewCounter(prometheus.CounterOpts{ //prom variable for connection count
		Name: "oskar_interview_new_connections_count",
		Help: "Number of new connections attempts since program start",
	})
)

var detectScanInterval int = 60 // seconds
var scanThreshold int = 3       // minimum ports tried to consider a port scanning attempt

var connMap = make(map[uint32][]uint16)
var lock = sync.RWMutex{}

func runExporter() {
	http.Handle("/metrics", promhttp.Handler())

	log.Print("Running prometheus exporter")
	http.ListenAndServe(":2112", nil)
}

func detectPortScan() {
	log.Print("Starting port scan detector")

	denyHash, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/deny_hash", nil)

	if err != nil {
		panic(fmt.Sprint("Error opening map:", err))
	}

	defer denyHash.Close()

	for {
		time.Sleep(time.Duration(detectScanInterval) * time.Second) // wait for a specified interval

		lock.Lock()
		for ip, ports := range connMap {
			if len(ports) >= scanThreshold {
				// below is not ideal, however my golang skillz are somehow limited so
				// this allows fir easy representation of an slice
				// create temporary slice
				p := []uint16{}
				for _, port := range ports {
					// convert ports to human readable (proper endianness)
					p = append(p, btos16(port))
				}
				log.Print("PORT SCAN DETECTED! ", ipv4.ToDots(btos32(ip)), " was trying to connect to ", p)
				err := denyHash.Put(ip, uint32(1))
				if err != nil {
					panic(fmt.Sprint("Error putting:", err))
				}
			}
		}

		connMap = make(map[uint32][]uint16) // clean the map
		lock.Unlock()
	}
}

func main() {
	var conn connection

	go runExporter()    // run exporter in separate routine
	go detectPortScan() // run port scanner detector

	queue, err := ebpf.LoadPinnedMap("/sys/fs/bpf/tc/globals/conn_map", nil)

	if err != nil {
		panic(fmt.Sprint("Error opening map:", err))
	}

	defer queue.Close()

	// main loop
	for {
		if err := queue.LookupAndDelete(nil, unsafe.Pointer(&conn)); err != nil { //try to get a queue entry and delete it afterwards, keep the queue clean!
			//			log.Print("Can't lookup and delete element:", err)
			time.Sleep(time.Second) // wait for a second, if queue is empty no need to fetch it again immediately
			continue
		}

		newConnectionsCount.Inc()                                                                                                         // increase the number of new connections
		log.Print(ipv4.ToDots(btos32(conn.sip)), ":", btos16(conn.sport), " -> ", ipv4.ToDots(btos32(conn.dip)), ":", btos16(conn.dport)) // debug output

		lock.Lock()
		if !contains(connMap[conn.sip], conn.dport) { // check if port already added (multiple connections to the same port are OK). This method is semi efficient, there are other ways to do it.
			connMap[conn.sip] = append(connMap[conn.sip], conn.dport) //add a SOURCE ip as key and DESTINATION PORT in a slice to get number of destination ports by source ip. Enough for this use case.
		}
		lock.Unlock()
	}

}

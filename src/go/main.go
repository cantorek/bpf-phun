package main

import (
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

var lock = sync.RWMutex{}

func runExporter() {
	http.Handle("/metrics", promhttp.Handler())

	log.Print("Running prometheus exporter")
	http.ListenAndServe(":2112", nil)
}

type Filter struct {
	connMapPath string
	denyMapPath string

	connQueue *ebpf.Map
	denyHash  *ebpf.Map
	connMap   map[uint32][]uint16

	/*
		Init()
		Block()
		OpenMap()
		Scan()
		ScanLoop()
		Count()
	*/
}

func (f *Filter) Init() error {
	var err error
	f.connQueue, err = OpenMap(f.connMapPath)

	if err != nil {
		log.Panic("Error initializing filter:", err)
		return err // i know that this will never be reached but it's easier to read this way, at least for me
	}

	f.denyHash, err = OpenMap(f.denyMapPath)
	if err != nil {
		log.Panic("Error initializing filter:", err)
		return err
	}

	return nil
}

func OpenMap(path string) (*ebpf.Map, error) {
	log.Print("Opening BPF map at: ", path)

	_map, err := ebpf.LoadPinnedMap(path, nil)

	if err != nil {
		log.Panic("Error opening map:", err)
		return nil, err
	}

	return _map, nil

}

func (f *Filter) Block(ip uint32) error {
	err := f.denyHash.Put(ip, uint32(1))
	if err != nil {
		log.Panic("Error putting:", err)
		return err
	}

	return nil
}

func (f *Filter) Scan() {
	for ip, ports := range f.connMap {
		if len(ports) >= scanThreshold {
			// below is not ideal, however my golang skillz are somehow limited so
			// this allows fir easy representation of an slice
			// create temporary slice
			p := []uint16{}
			for _, port := range ports {
				// convert ports to human readable (proper endianness)
				p = append(p, btos16(port))
			}
			f.Block(ip) // block given ip
			log.Print("PORT SCAN DETECTED! ", ipv4.ToDots(btos32(ip)), " was trying to connect to ", p)
		}
	}
}

func (f *Filter) ScanLoop() {
	log.Print("Starting port scan detector")

	for {
		time.Sleep(time.Duration(detectScanInterval) * time.Second) // wait for a specified interval

		lock.Lock()

		f.Scan() // scan connMap for ports scanning attempts

		f.connMap = make(map[uint32][]uint16) // clean the map
		lock.Unlock()
	}
}

func (f *Filter) Count() error {
	var conn connection

	if err := f.connQueue.LookupAndDelete(nil, unsafe.Pointer(&conn)); err != nil { //try to get a queue entry and delete it afterwards, keep the queue clean!
		//log.Print("Can't lookup and delete element:", err)
		return err
	}

	newConnectionsCount.Inc()                                                                                                         // increase the number of new connections
	log.Print(ipv4.ToDots(btos32(conn.sip)), ":", btos16(conn.sport), " -> ", ipv4.ToDots(btos32(conn.dip)), ":", btos16(conn.dport)) // debug output

	lock.Lock()
	if !contains(f.connMap[conn.sip], conn.dport) { // check if port already added (multiple connections to the same port are OK). This method is semi efficient, there are other ways to do it (hash), but for now it's enough.
		f.connMap[conn.sip] = append(f.connMap[conn.sip], conn.dport) //add a SOURCE ip as key and DESTINATION PORT in a slice to get number of destination ports by source ip. Enough for this use case.
	}
	lock.Unlock()

	return nil
}

func main() {

	go runExporter() // run exporter in separate routine

	filter := Filter{
		"/sys/fs/bpf/tc/globals/conn_map",
		"/sys/fs/bpf/tc/globals/deny_hash",
		nil,
		nil,
		make(map[uint32][]uint16)}

	filter.Init()
	go filter.ScanLoop()

	defer filter.connQueue.Close()
	defer filter.denyHash.Close()

	// main loop
	for {
		err := filter.Count()
		if err != nil {
			time.Sleep(time.Second) // wait for a second, if queue is empty no need to fetch it again immediately, this of course could need a fine tuning as busy system can fill up the queue in 1 second
		}
	}
}

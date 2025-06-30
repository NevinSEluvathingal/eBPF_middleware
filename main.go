package main

import (
    "fmt"
    "net"
    "os"
    "os/signal"
    "syscall"
    "github.com/gorilla/websocket"
    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/perf"
)

var upgrader=websocket.upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type UserDownstreamEvent struct {
    Bytes uint64
    IP    uint32
    MAC   [6]byte
}

func ipToString(ip uint32) string {
    b := make([]byte, 4)
    binary.LittleEndian.PutUint32(b, ip)
    return net.IP(b).String()
}

func isMulticastIP(ip net.IP) bool {
    return ip.IsMulticast()
}


func macToKey(mac net.HardwareAddr) [6]byte {
    var key [6]byte
    copy(key[:], mac)
    return key
}

func ipHandler(w http.ResponseWriter,r *http.Request) {
    var ips []string	
    err := json.NewDecoder(r.Body).Decode(&ips)

    fmt.Println("recieved ip ")

    blockedMap := coll.Maps["mac_blocklist"]
    if blockedMap == nil {
        panic("Map 'blocked_macs' not found")
    }

    // 🛑 Add a blocked MAC
    mac, err := net.ParseMAC(ips[0])
    if err != nil {
        panic(fmt.Sprintf("Invalid MAC: %v", err))
    }
    key := macToKey(mac)
    value := uint8(1)

    err = blockedMap.Put(key, value)
    if err != nil {
        panic(fmt.Sprintf("Failed to insert MAC: %v", err))
    }

    fmt.Printf("Blocked MAC %s\n", mac.String())
    w.Header().Set("Content-Type","application/json")
}

func speedHandler(w http.ResponseWriter,r *http.Request){
    conn,err := upgrader.upgrade(w,r,nil)
    if err != nil {
	fmt.Println("upgrade error:",err)
    }
    defer conn.Close()

    perfMap, ok := coll.Maps["perf_events"]
    if !ok {
        panic("Map 'perf_events' not found")
    }

    reader, err := perf.NewReader(perfMap, 4096)
    if err != nil {
        panic(fmt.Sprintf("Failed to create perf event reader: %v", err))
    }
    defer reader.Close()

    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

    fmt.Println("Listening for downstream user packet events...")
    go func() {
        for {
            record, err := reader.Read()
            if err != nil {
                fmt.Printf("Error reading from perf event reader: %v\n", err)
                continue
            }

            if record.LostSamples != 0 {
                fmt.Printf("Lost %d samples\n", record.LostSamples)
                continue
            }

            if len(record.RawSample) < 18 {
                fmt.Println("Invalid sample size")
                continue
            }

            var event UserDownstreamEvent
            event.Bytes = binary.LittleEndian.Uint64(record.RawSample[0:8])
            event.IP = binary.LittleEndian.Uint32(record.RawSample[8:12])
            copy(event.MAC[:], record.RawSample[12:18])

            ip := net.IPv4(byte(event.IP), byte(event.IP>>8), byte(event.IP>>16), byte(event.IP>>24))
            if isMulticastIP(ip) {
                continue
            }
            if err := conn.WriteJSON(data); err != nil {
		fmt.Println("write error",err)
		break
	    }
	  time.Sleep(time.Second)
       }
    }
}
func main() {
    iface := os.Getenv("INTERFACE")
    if iface == "" {
        panic("Set INTERFACE env var (e.g. INTERFACE=wlp2s0)")
    }

    // Load eBPF objects
    spec, err := ebpf.LoadCollectionSpec("ebpf.o")
    if err != nil {
        panic(fmt.Sprintf("Failed to load BPF spec: %v", err))
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        panic(fmt.Sprintf("Failed to load BPF collection: %v", err))
    }
    defer coll.Close()

    // Attach XDP program
    prog := coll.Programs["count_downstream"]
    if prog == nil {
        panic("Program 'count_downstream' not found")
    }

    ifaceObj, err := net.InterfaceByName(iface)
    if err != nil {
        panic(fmt.Sprintf("Interface error: %v", err))
    }

    lnk, err := link.AttachXDP(link.XDPOptions{
        Program:   prog,
        Interface: ifaceObj.Index,
    })
    if err != nil {
        panic(fmt.Sprintf("Failed to attach XDP: %v", err))
    }
    defer lnk.Close()
    fmt.Println("XDP program attached.")

    http.HandleFunc("/ws",ipHandler)
    http.HandleFunc("/data",speedHandler)

    // Handle Ctrl+C
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
    <-sig

    fmt.Println("Detaching XDP...")
}

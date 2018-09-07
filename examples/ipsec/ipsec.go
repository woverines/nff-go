// Only IPv4, Only tunnel, Only ESP, Only AES-128-CBC
package main

import "github.com/intel-go/nff-go/flow"
import "flag"

func main() {
	outport := flag.Uint("outport", 1, "port for sender")
	inport := flag.Uint("inport", 0, "port for receiver")
	noscheduler := flag.Bool("no-scheduler", false, "disable scheduler")
	dpdkLogLevel := flag.String("dpdk", "--log-level=0", "Passes an arbitrary argument to dpdk EAL")
	cores := flag.String("cores", "0-10", "Cores mask. Avoid hyperthreading here")
	vector := flag.Bool("v", false, "vector version")
	dec := flag.Bool("d", false, "decapsulate after encapsulation")

	flag.Parse()

	config := flow.Config{
		DisableScheduler: *noscheduler,
		DPDKArgs:         []string{*dpdkLogLevel},
		CPUList:          *cores,
	}
	flow.SystemInit(&config)
	input, _ := flow.SetReceiver(uint16(*inport))
	if *vector {
		flow.SetVectorHandlerDrop(input, vectorEncapsulation, vContext{})
	} else {
		flow.SetHandlerDrop(input, scalarEncapsulation, sContext{})
	}
	if *dec {
		flow.SetHandlerDrop(input, decapsulation, sContext{})
	}
	flow.SetSender(input, uint16(*outport))
	flow.SystemStart()
}

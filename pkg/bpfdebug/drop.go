// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpfdebug

import (
	"fmt"
	clientPkg "github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/api/v1/models"
	"strconv"
	"github.com/spf13/viper"
)

const (
	// DropNotifyLen is the amount of packet data provided in a drop notification
	DropNotifyLen = 32
)

type EndpointInfoCache map[int]*models.Endpoint

var (
	endpointInfoCache = make(EndpointInfoCache)
	client, _ = clientPkg.NewClient(viper.GetString("host"))
)
// DropNotify is the message format of a drop notification in the BPF ring buffer
type DropNotify struct {
	Type     uint8
	SubType  uint8
	Source   uint16
	Hash     uint32
	OrigLen  uint32
	CapLen   uint32
	SrcLabel uint32
	DstLabel uint32
	DstID    uint32
	Ifindex  uint32
	// data
}

var errors = map[uint8]string{
	0:   "Success",
	2:   "Invalid packet",
	130: "Invalid source mac",
	131: "Invalid destination mac",
	132: "Invalid source ip",
	133: "Policy denied",
	134: "Invalid packet",
	135: "CT: Truncated or invalid header",
	136: "CT: Missing TCP ACK flag",
	137: "CT: Unknown L4 protocol",
	138: "CT: Can't create entry from packet",
	139: "Unsupported L3 protocol",
	140: "Missed tail call",
	141: "Error writing to packet",
	142: "Unknown L4 protocol",
	143: "Unknown ICMPv4 code",
	144: "Unknown ICMPv4 type",
	145: "Unknown ICMPv6 code",
	146: "Unknown ICMPv6 type",
	147: "Error retrieving tunnel key",
	148: "Error retrieving tunnel options",
	149: "Invalid Geneve option",
	150: "Unknown L3 target address",
	151: "Not a local target address",
	152: "No matching local container found",
	153: "Error while correcting L3 checksum",
	154: "Error while correcting L4 checksum",
	155: "CT: Map insertion failed",
	156: "Invalid IPv6 extension header",
	157: "IPv6 fragmentation not supported",
	158: "Service backend not found",
	159: "Policy denied (L4)",
	160: "No tunnel/encapsulation endpoint",
}

func dropReason(reason uint8) string {
	if err, ok := errors[reason]; ok {
		return err
	}
	return fmt.Sprintf("%d", reason)
}

// getEndpoint gets the endpoint object mapping to the corresponding eId.
func (cache EndpointInfoCache) getEndpoint(eId int) (*models.Endpoint, error) {
	if ep, ok := cache[eId]; !ok {
		epGet, err := client.EndpointGet(strconv.Itoa(eId))
		if err != nil {
			return nil, fmt.Errorf("error retrieving information from Cilium API for endpoint %d\n", eId)
		}
		cache[eId] = epGet
	} else {
		if ep.Identity == nil {
			epGet, err := client.EndpointGet(strconv.Itoa(eId))
			if err != nil {
				return nil, fmt.Errorf("error retrieving information from Cilium API for endpoint %d\n", eId)
			}
			if epGet.Identity != nil {
				cache[eId] = epGet
			}
		}
	}
	return cache[eId], nil
}

func (n *DropNotify) DumpInfo(data []byte) {
	ep2, err := endpointInfoCache.getEndpoint(int(n.Source))
	if err != nil {
		fmt.Printf(err.Error())
	} else {
		if ep2.Identity == nil {
			fmt.Printf("[%v]:%d (nil secID) %d bytes dropped (%s)\n", ep2.Addressing.IPV4, n.Source, n.OrigLen, dropReason(n.SubType))
		} else {
			if n.DstID == 0 {
				fmt.Printf("[%v]:%d (id %d) > (%d id) %d bytes dropped (%s)\n", ep2.Addressing.IPV4, n.Source, ep2.Identity.ID, n.DstID, n.OrigLen, dropReason(n.SubType))
			} else {
				ep3, err := endpointInfoCache.getEndpoint(int(n.DstID))
				if err != nil {
					fmt.Printf(err.Error())
				} else {
					fmt.Printf("[%v]:%d (%v) > (%v / %d id) %d bytes dropped (%s)\n", ep2.Addressing.IPV4, n.Source, ep2.Identity.ID, ep3.Addressing.IPV4, n.DstID, n.OrigLen, dropReason(n.SubType))
				}
			}
		}
	}
}

// Dump prints the drop notification in human readable form
func (n *DropNotify) DumpVerbose(dissect bool, data []byte, prefix string) {
	fmt.Printf("%s MARK %#x FROM %d Packet dropped %d (%s) %d bytes ifindex=%d",
		prefix, n.Hash, n.Source, n.SubType, dropReason(n.SubType), n.OrigLen, n.Ifindex)

	if n.SrcLabel != 0 || n.DstLabel != 0 {
		fmt.Printf(" %d->%d", n.SrcLabel, n.DstLabel)
	}

	if n.DstID != 0 {
		fmt.Printf(" to lxc %d\n", n.DstID)
	} else {
		fmt.Printf("\n")
	}

	if n.CapLen > 0 && len(data) > DropNotifyLen {
		Dissect(dissect, data[DropNotifyLen:])
	}
}

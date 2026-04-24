package models

import "time"

// The struct created will represent the simplified data we are going to track

type PacketInfo struct {
	Timestamp	string	`json:"timestamp"`
	Source	string	`json:"source"`
	Dest	string	`json:"dest"`
	Protocol	string	`json:"protocol"`
	Info	string	`json:"info"`
	PID	int32	`json:"pid"`
	Processes	string	`json:"process"`
}

func NewPacketInfo(src, dst, proto, info string) PacketInfo {
	return PacketInfo{
		Timestamp:	time.Now().Format(time.RFC3339),
		Source:	src,
		Dest:	dst,
		Protocol:	proto,
		Info:	info,
	}
}
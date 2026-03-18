package network

type Packet struct {
	ID           int
	Src          string
	CreationTime float64
	IsFlagged    bool
}

func NewPacket(id int, src string, time float64) Packet {
	return Packet{
		ID:           id,
		Src:          src,
		CreationTime: time,
	}
}

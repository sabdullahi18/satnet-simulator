package network

type Packet struct {
	ID       int
	BatchID  int
	Src      string
	SentTime float64

	DelayComponents

	IsTargeted      bool
	HasIncompetence bool
	IsFlagged       bool
}

func NewPacket(id, batchID int, src string, time float64) Packet {
	return Packet{
		ID:       id,
		BatchID:  batchID,
		Src:      src,
		SentTime: time,
	}
}

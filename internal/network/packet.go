package network

type Packet struct {
	ID           int
	BatchID      int
	Src          string
	CreationTime float64
	IsFlagged    bool
}

func NewPacket(id, batchID int, src string, time float64) Packet {
	return Packet{
		ID:           id,
		BatchID:      batchID,
		Src:          src,
		CreationTime: time,
	}
}

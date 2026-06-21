package network

type Packet struct {
	ID       int
	BatchID  int
	Src      string
	SentTime float64

	BaseDelay         float64
	IncompetenceDelay float64
	DeliberateDelay   float64
	ActualDelay       float64

	WasDelayed      bool
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

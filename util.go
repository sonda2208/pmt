package pmt

import "encoding/binary"

func toLengthValue(chunks ...string) []byte {
	var out []byte
	for _, chunk := range chunks {
		lenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(lenBuf, uint32(len(chunk)))
		out = append(out, lenBuf...)
		out = append(out, []byte(chunk)...)
	}

	return out
}

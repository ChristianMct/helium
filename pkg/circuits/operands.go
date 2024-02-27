package circuits

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

type OperandLabel string

type Operand struct {
	OperandLabel
	*rlwe.Ciphertext
}

type FutureOperand struct {
	Operand
	c chan struct{}
}

// FutureOperand must have labels
func NewFutureOperand(opl OperandLabel) *FutureOperand {
	return &FutureOperand{Operand: Operand{OperandLabel: opl}, c: make(chan struct{})}
}

func NewDummyFutureOperand(opl OperandLabel) *FutureOperand {
	c := make(chan struct{})
	close(c)
	return &FutureOperand{Operand: Operand{OperandLabel: opl}, c: c}
}

func (fo *FutureOperand) Set(op Operand) {
	if fo.Ciphertext != nil { // TODO that only the main circuit routine calls set
		return
	}
	fo.Ciphertext = op.Ciphertext
	close(fo.c)
}

func (fo *FutureOperand) Get() Operand {
	<-fo.c
	return fo.Operand
}

func (opl OperandLabel) Host() pkg.NodeID {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	return pkg.NodeID(nopl.Host)
}

func (opl OperandLabel) Circuit() ID {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	return ID(strings.Trim(path.Dir(nopl.Path), "/"))
}

func (opl OperandLabel) HasHost(id pkg.NodeID) bool {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	return nopl.Host == string(id)
}

func (opl OperandLabel) ForCircuit(cid ID) OperandLabel {
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	nopl.Path = fmt.Sprintf("/%s%s", cid, nopl.Path)
	return OperandLabel(nopl.String())
}

func (opl OperandLabel) ForMapping(nodeMapping map[string]pkg.NodeID) OperandLabel {
	if nodeMapping == nil {
		return opl
	}
	nopl, err := url.Parse(string(opl))
	if err != nil {
		panic(fmt.Errorf("invalid operand label: %s", opl))
	}
	if len(nopl.Host) > 0 {
		nodeID, provided := nodeMapping[nopl.Host]
		if !provided {
			panic(fmt.Errorf("no mapping provided for node id %s", nopl.Host))
		}
		nopl.Host = string(nodeID)
	}
	return OperandLabel(nopl.String())
}

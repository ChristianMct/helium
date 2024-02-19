package compute

import (
	"context"

	"github.com/ldsec/helium/pkg/circuits"
	"github.com/ldsec/helium/pkg/pkg"
)

type participant struct {
	trans Transport
}

func NewParticipant(trans Transport) *participant {
	return &participant{
		trans: trans,
	}
}

func (p *participant) IncomingOperand(_ circuits.Operand) error {
	panic("participant should not receive incoming operands")
}

func (p *participant) GetOperand(ctx context.Context, opl circuits.OperandLabel) (*circuits.Operand, bool) {
	pkgct, err := p.trans.GetCiphertext(ctx, pkg.CiphertextID(opl))
	if err != nil {
		return nil, false
	}

	return &circuits.Operand{OperandLabel: opl, Ciphertext: &pkgct.Ciphertext}, true
}

func (p *participant) GetFutureOperand(ctx context.Context, opl circuits.OperandLabel) (*circuits.FutureOperand, bool) {

	fop := circuits.NewFutureOperand(opl)

	go func() {
		op, _ := p.GetOperand(ctx, opl)
		fop.Set(*op)
	}()

	return fop, true
}

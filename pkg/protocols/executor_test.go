package protocols

import (
	"fmt"
	"testing"

	"github.com/ldsec/helium/pkg/pkg"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/stretchr/testify/require"
)

func TestExecutor(t *testing.T) {

	for _, ts := range testSettings {

		if ts.T == 0 {
			ts.T = ts.N
		}

		params := TestPN12QP109

		hid := pkg.NodeID("helper")
		testSess, err := pkg.NewTestSession(ts.N, ts.T, params, hid)
		if err != nil {
			t.Fatal(err)
		}
		sessParams := testSess.SessParams
		nids := utils.NewSet(sessParams.Nodes)

		ctx := pkg.NewContext(&sessParams.ID, nil)

		executors := make(map[pkg.NodeID]*Executor, len(nids))
		testTrans := NewTestTransport()
		//testCoord := newTestCoordinator()
		helper, err := NewExectutor(hid, testSess.HelperSession, testTrans)
		require.Nil(t, err)
		go helper.RunService(ctx)
		for nid := range nids {
			executors[nid], err = NewExectutor(nid, testSess.NodeSessions[nid], testTrans.TransportFor(nid))
			require.Nil(t, err)
			go executors[nid].RunService(ctx)
		}

		sigs := []Signature{
			{Type: CKG},
			{Type: RTG, Args: map[string]string{"GalEl": "5"}},
			{Type: RKG},
			//{Type: DEC, Args: map[string]string{"target": "node-0", "smudging": "40"}},
		}

		for _, sig := range sigs {
			parts, err := GetParticipants(sig, nids, ts.T)
			if err != nil {
				t.Fatal(err)
			}
			pd := Descriptor{Signature: sig, Participants: parts, Aggregator: hid}
			t.Run(fmt.Sprintf("N=%d/T=%d/Sig=%s", ts.N, ts.T, pd.Signature), func(t *testing.T) {
				var input Input
				if pd.Signature.Type == RKG {
					r1pd := pd
					r1pd.Signature.Type = RKG_1
					aggOutR1C, err := helper.RunProtocol(ctx, r1pd)
					for _, exec := range executors {
						go exec.RunProtocol(ctx, r1pd)
					}
					aggOutR1 := <-aggOutR1C
					require.Nil(t, err)
					require.Nil(t, aggOutR1.Error)
					input = aggOutR1.Share
				}
				aggOutC, err := helper.RunProtocol(ctx, pd, input)
				for _, exec := range executors {
					go exec.RunProtocol(ctx, pd, input)
				}
				require.Nil(t, err)
				aggOut := <-aggOutC
				out := helper.GetOutput(ctx, pd, aggOut, input)
				checkOutput(out, pd, *testSess, t)
			})
		}
	}
}

package pkg

import (
	"context"
	"fmt"
	"log"
	"math/rand"

	"github.com/ldsec/helium/pkg/objectstore"
	"github.com/ldsec/helium/pkg/utils"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"google.golang.org/grpc/metadata"

	"github.com/tuneinsight/lattigo/v4/drlwe"

	"sync"
)

type NodesList []struct {
	NodeID
	NodeAddress
	DelegateID NodeID
}

func (nl NodesList) String() string {
	str := "[ "
	for _, node := range nl {
		str += fmt.Sprintf(`{ ID: %s, Address: %s, DelegateID: %s } `,
			node.NodeID, node.NodeAddress, node.DelegateID)
	}
	return str + "]"
}

type SessionID string

type ProtocolID string

type CircuitID string

type NodeID string

type NodeAddress string

type ctxKey string

var (
	ctxSessionID ctxKey = "session_id"
	ctxCircuitID ctxKey = "circuit_id"
)

func NewContext(sessID *SessionID, circID *CircuitID) context.Context {
	ctx := context.Background()
	if sessID != nil {
		ctx = context.WithValue(ctx, ctxSessionID, *sessID)
	}
	if circID != nil {
		ctx = AppendCircuitID(ctx, *circID)
	}
	return ctx
}

func NewOutgoingContext(senderID *NodeID, sessID *SessionID, circID *CircuitID) context.Context {
	md := metadata.New(nil)
	if senderID != nil {
		md.Append("sender_id", string(*senderID))
	}
	if sessID != nil {
		md.Append(string(ctxSessionID), string(*sessID))
	}
	if circID != nil {
		md.Append(string(ctxCircuitID), string(*circID))
	}
	return metadata.NewOutgoingContext(context.Background(), md)
}

func GetOutgoingContext(ctx context.Context, senderID NodeID) context.Context {
	md := metadata.New(nil)
	md.Append("sender_id", string(senderID))
	if sessID, hasSessID := SessionIDFromContext(ctx); hasSessID {
		md.Append(string(ctxSessionID), string(sessID))
	}
	if circID, hasCircID := CircuitIDFromContext(ctx); hasCircID {
		md.Append(string(ctxCircuitID), string(circID))
	}
	return metadata.NewOutgoingContext(ctx, md)
}

func AppendCircuitID(ctx context.Context, circID CircuitID) context.Context {
	return context.WithValue(ctx, ctxCircuitID, circID)
}

func ValueFromIncomingContext(ctx context.Context, key string) string {
	md, hasMd := metadata.FromIncomingContext(ctx)
	if !hasMd {
		return ""
	}
	id := md.Get(key)
	if len(id) < 1 {
		return ""
	}
	return id[0]
}

func SenderIDFromIncomingContext(ctx context.Context) NodeID {
	return NodeID(ValueFromIncomingContext(ctx, "sender_id"))
}

func SessionIDFromIncomingContext(ctx context.Context) SessionID {
	return SessionID(ValueFromIncomingContext(ctx, string(ctxSessionID)))
}

func CircuitIDFromIncomingContext(ctx context.Context) CircuitID {
	return CircuitID(ValueFromIncomingContext(ctx, string(ctxCircuitID)))
}

func SessionIDFromContext(ctx context.Context) (SessionID, bool) {
	sessID, ok := ctx.Value(ctxSessionID).(SessionID)
	return sessID, ok
}

func CircuitIDFromContext(ctx context.Context) (CircuitID, bool) {
	circID, isValid := ctx.Value(ctxCircuitID).(CircuitID)
	return circID, isValid
}

func (na NodeAddress) String() string {
	return string(na)
}

func (pid ProtocolID) String() string {
	return string(pid)
}

// Session is the context of an MPC protocol execution.
type Session struct {
	ID     SessionID
	NodeID NodeID
	Nodes  []NodeID

	T    int
	SPKS map[NodeID]drlwe.ShamirPublicPoint
	//sk       *rlwe.SecretKey
	//tsk      *drlwe.ShamirSecretShare
	rlkEphSk *rlwe.SecretKey

	PublicSeed []byte
	Params     *rlwe.Parameters

	*CiphertextStore
	objectstore.ObjectStore

	mutex sync.RWMutex
}

// SessionParameters contains data used to initialize a Session.
type SessionParameters struct {
	ID                      SessionID
	Nodes                   []NodeID
	RLWEParams              rlwe.ParametersLiteral
	T                       int
	ShamirPks               map[NodeID]drlwe.ShamirPublicPoint
	PublicSeed, PrivateSeed []byte
}

func NewSession(sessParams SessionParameters, nodeID NodeID, objStore objectstore.ObjectStore) (sess *Session, err error) {
	sess = new(Session)
	sess.NodeID = nodeID
	sess.ObjectStore = objStore
	sess.ID = sessParams.ID
	sess.Nodes = sessParams.Nodes
	if sessParams.T > 0 && sessParams.T < len(sessParams.Nodes) {
		sess.T = sessParams.T
	} else {
		sess.T = len(sessParams.Nodes)
	}
	sess.PublicSeed = sessParams.PublicSeed
	sess.SPKS = make(map[NodeID]drlwe.ShamirPublicPoint, len(sessParams.ShamirPks))
	for id, spk := range sessParams.ShamirPks {
		sess.SPKS[id] = spk
	}

	params, err := rlwe.NewParametersFromLiteral(sessParams.RLWEParams)
	sess.Params = &params

	if sessParams.T == 0 {
		sessParams.T = len(sessParams.Nodes)
	}

	kgen := rlwe.NewKeyGenerator(*sess.Params)

	// node generates its secret-key for the session
	if utils.NewSet(sessParams.Nodes).Contains(nodeID) {

		sk, errSk := sess.GetSecretKey()
		tsk, errTsk := sess.GetThresholdSecretKey()

		if errSk != nil || errTsk != nil {
			log.Printf("%s | no sk and tsk found, node will generate them\n", sess.NodeID)
			sk, tsk, err = GetTestSecretKeys(sessParams, nodeID) // TODO: local generation for testing
			if err != nil {
				panic(err)
			}
			sess.SetSecretKey(sk)
			if tsk != nil {
				sess.SetThresholdSecretKey(tsk)
			}
		}

		sess.rlkEphSk = kgen.GenSecretKeyNew()
		sess.SetRLKEphemeralSecretKey(sess.rlkEphSk)
	} else {
		sk, pk := kgen.GenKeyPairNew()
		sess.SetSecretKey(sk)
		sess.SetPublicKey(pk)
	}

	//sess.Combiner = drlwe.NewCombiner(*params, shamirPts[nodeID], spts, t)
	sess.CiphertextStore = NewCiphertextStore()

	return sess, nil
}

// GetCollectivePublicKey loads the collective public key from the ObjectStore.
func (s *Session) GetCollectivePublicKey() (*rlwe.PublicKey, error) {
	cpk := new(rlwe.PublicKey)

	if err := s.ObjectStore.Load("CKG()", cpk); err != nil {
		return nil, fmt.Errorf("error while loading the collective public key: %w", err)
	}

	return cpk, nil
}

// SetCollectivePublicKey stores the collective public key into the ObjectStore.
func (s *Session) SetCollectivePublicKey(cpk *rlwe.PublicKey) error {
	if err := s.ObjectStore.Store("CKG()", cpk); err != nil {
		return fmt.Errorf("error while storing the collective public key: %w", err)
	}

	return nil
}

// GetRelinearizationKey loads the relinearization key from the ObjectStore.
func (s *Session) GetRelinearizationKey() (*rlwe.RelinearizationKey, error) {
	rlk := new(rlwe.RelinearizationKey)

	if err := s.ObjectStore.Load("RKG_2()", rlk); err != nil {
		return nil, fmt.Errorf("error while loading the relinearization key: %w", err)
	}

	return rlk, nil
}

// SetRelinearizationKey stores the relinearization key into the ObjectStore.
func (s *Session) SetRelinearizationKey(rlk *rlwe.RelinearizationKey) error {
	if err := s.ObjectStore.Store("RKG_2()", rlk); err != nil {
		return fmt.Errorf("error while storing the relinearization key: %w", err)
	}

	return nil
}

// SetRotationKey loads the rotation key identified by the Galois element from the ObjectStore.
func (s *Session) GetRotationKey(galEl uint64) (*rlwe.GaloisKey, error) {
	rtk := new(rlwe.GaloisKey)
	if err := s.ObjectStore.Load(fmt.Sprintf("RTG(GalEl=%d)", galEl), rtk); err != nil {
		return nil, fmt.Errorf("error while loading the rotation key with galEl %d: %w", galEl, err)
	}

	return rtk, nil
}

// SetRotationKey stores the rotation key identified by the Galois element into the ObjectStore.
func (s *Session) SetRotationKey(rtk *rlwe.GaloisKey, galEl uint64) error {
	if err := s.ObjectStore.Store(fmt.Sprintf("RTG(GalEl=%d)", galEl), rtk); err != nil {
		return fmt.Errorf("error while storing the rotation key with galEl %d: %w", galEl, err)
	}

	return nil
}

func (s *Session) GetPublicKey() (*rlwe.PublicKey, error) {
	cpk := new(rlwe.PublicKey)

	if err := s.ObjectStore.Load("PK", cpk); err != nil {
		return nil, fmt.Errorf("error while loading the collective public key: %w", err)
	}

	return cpk, nil
}

func (s *Session) SetPublicKey(cpk *rlwe.PublicKey) error {
	if err := s.ObjectStore.Store("PK", cpk); err != nil {
		return fmt.Errorf("error while storing the collective public key: %w", err)
	}

	return nil
}

// GetOutputPkForNode loads the output public key for a node from the ObjectStore.
func (s *Session) GetOutputPkForNode(nid NodeID) (pk *rlwe.PublicKey, exists error) {
	outputPk := rlwe.NewPublicKey(*s.Params)

	if err := s.ObjectStore.Load(fmt.Sprintf("PK(Sender=%s)", nid), outputPk); err != nil {
		return nil, fmt.Errorf("error while loading the output public key of node %s: %w", nid, err)
	}

	return outputPk, nil
}

// SetOutputPkForNode stores the output public key for a node into the ObjectStore.
func (s *Session) SetOutputPkForNode(nid NodeID, outputPk *rlwe.PublicKey) error {
	if err := s.ObjectStore.Store(fmt.Sprintf("PK(Sender=%s)", nid), outputPk); err != nil {
		return fmt.Errorf("error while storing the output public key of node %s: %w", nid, err)
	}

	return nil
}

func (sess *Session) GetSecretKeyForGroup(parties []NodeID) (sk *rlwe.SecretKey, err error) {
	switch {
	case len(parties) == len(sess.Nodes):
		sk, err := sess.GetSecretKey()
		if err != nil {
			return nil, err
		}
		if sk == nil {
			return nil, fmt.Errorf("party has no secret-key in the session")
		}
		return sk, nil
	case len(parties) >= sess.T:
		sk = rlwe.NewSecretKey(*sess.Params)
		spks := make([]drlwe.ShamirPublicPoint, len(parties))
		for i, pid := range parties {
			spks[i] = sess.SPKS[pid]
		}
		tsk, err := sess.GetThresholdSecretKey()
		if err != nil {
			return nil, err
		}
		drlwe.NewCombiner(*sess.Params,
			sess.GetShamirPublicPoints()[sess.NodeID],
			sess.GetShamirPublicPointsList(),
			sess.T).GenAdditiveShare(spks, sess.SPKS[sess.NodeID], *tsk, sk)
		return sk, nil
	default:
		return nil, fmt.Errorf("not enough participants to reconstruct")
	}
}

// // GetOutputSk loads the output secret key of this node from the ObjectStore.
// func (s *Session) GetOutputSk() (*rlwe.SecretKey, error) {
// 	outputSk := rlwe.NewSecretKey(*s.Params)

// 	if err := s.ObjectStore.Load("outputSK", outputSk); err != nil {
// 		return nil, fmt.Errorf("error while loading the output secret key: %w", err)
// 	}

// 	return outputSk, nil
// }

// // SetOuputSk stores the output secret key of this node into the ObjectStore.
// func (s *Session) SetOuputSk(outputSk *rlwe.SecretKey) error {
// 	if err := s.ObjectStore.Store("outputSK", outputSk); err != nil {
// 		return fmt.Errorf("error while storing the output secret key: %w", err)
// 	}

// 	return nil
// }

// GetSecretKey loads the secret key from the ObjectStore.
func (s *Session) GetSecretKey() (*rlwe.SecretKey, error) {
	sk := new(rlwe.SecretKey)
	if err := s.ObjectStore.Load("sessionSK", sk); err != nil {
		return nil, fmt.Errorf("error while loading the session secret key: %w", err)
	}

	return sk, nil
}

func (s *Session) GetRLKEphemeralSecretKey() (*rlwe.SecretKey, error) {
	sk := new(rlwe.SecretKey)
	if err := s.ObjectStore.Load("rlkEphSK", sk); err != nil {
		return nil, fmt.Errorf("error while loading the session rlk ephemeral secret key: %w", err)
	}

	return sk, nil
}

// GetThresholdSecretKey loads the secret key from the ObjectStore.
func (s *Session) GetThresholdSecretKey() (*drlwe.ShamirSecretShare, error) {
	tsk := new(drlwe.ShamirSecretShare)
	if err := s.ObjectStore.Load("sessionThresholdSK", tsk); err != nil {
		return nil, fmt.Errorf("error while loading the session secret key: %w", err)
	}

	return tsk, nil
}

// SetSecretKey stores the secret key into the ObjectStore.
func (s *Session) SetSecretKey(sk *rlwe.SecretKey) error {
	if err := s.ObjectStore.Store("sessionSK", sk); err != nil {
		return fmt.Errorf("error while storing the session secret key: %w", err)
	}
	return nil
}

// SetThresholdSecretKey stores the secret key into the ObjectStore.
func (s *Session) SetThresholdSecretKey(tsk *drlwe.ShamirSecretShare) error {
	if err := s.ObjectStore.Store("sessionThresholdSK", tsk); err != nil {
		return fmt.Errorf("error while storing the session threshold secret key: %w", err)
	}
	return nil
}

func (s *Session) SetRLKEphemeralSecretKey(sk *rlwe.SecretKey) error {
	if err := s.ObjectStore.Store("rlkEphSK", sk); err != nil {
		return fmt.Errorf("error while storing the session rlk ephemeral  secret key: %w", err)
	}
	return nil
}

func (s *Session) GetShamirPublicPoints() map[NodeID]drlwe.ShamirPublicPoint {
	spts := make(map[NodeID]drlwe.ShamirPublicPoint, len(s.SPKS))
	for p, spt := range s.SPKS {
		spts[p] = spt
	}
	return spts
}

func (s *Session) GetShamirPublicPointsList() []drlwe.ShamirPublicPoint {
	spts := make([]drlwe.ShamirPublicPoint, 0, len(s.SPKS))
	for _, spt := range s.SPKS {
		spts = append(spts, spt)
	}
	return spts
}

func (s *Session) Contains(nodeID NodeID) bool {
	return utils.NewSet(s.Nodes).Contains(nodeID)
}

func GetRandomClientSlice(t int, nodes []NodeID) []NodeID {
	cid := make([]NodeID, len(nodes))
	copy(cid, nodes)
	rand.Shuffle(len(cid), func(i, j int) {
		cid[i], cid[j] = cid[j], cid[i]
	})
	return cid[:t]
}

func (s *Session) String() string {
	return fmt.Sprintf(`
	{
		ID: %s,
		NodeID: %s,
		Nodes: %v,
		T: %d,
		CRSKey: %v,
	}`, s.ID, s.NodeID, s.Nodes, s.T, s.PublicSeed)
}

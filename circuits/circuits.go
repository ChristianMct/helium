// Package circuits provides the types and interfaces for defining, parsing and executing circuits.
package circuits

import (
	"context"
	"fmt"
	"log"
	"maps"
	"strconv"
	"strings"
	"sync"

	"github.com/ChristianMct/helium/protocols"
	"github.com/ChristianMct/helium/sessions"
	"github.com/ChristianMct/helium/utils"
	"github.com/tuneinsight/lattigo/v5/core/rlwe"
	"github.com/tuneinsight/lattigo/v5/he"
	"github.com/tuneinsight/lattigo/v5/schemes/bgv"
	"github.com/tuneinsight/lattigo/v5/schemes/ckks"
)

// Circuit is a type for representing circuits, which are Go functions interacting with
// a provided evaluation runtime.
type Circuit func(Runtime) error

// Runtime defines the interface that is available to circuits to access
// their execution context.
type Runtime interface {
	Circuit() Descriptor

	Parameters() sessions.FHEParameters

	// Input reads an input operand with the given label from the context.
	// When specifying the label, the user:
	//  - can use a placeholder id for the node, the mapping for which is provided in the Signature.
	//  - can omit the session-id part as it wil be automatically resolved by the runtime.
	Input(OperandLabel) *FutureOperand

	// Load reads an existing ciphertext in the session
	// When specifying the label, the user:
	//  - can use a placeholder id for the node, the mapping for which is provided in the Signature.
	//  - can omit the session-id part as it wil be automatically resolved by the runtime.
	Load(OperandLabel) *Operand

	// NewOperand creates a new operand with the given label.
	// When specifying the label, the user:
	//  - can use a placeholder id for the node, the mapping for which is provided in the Signature.
	//  - can omit the session-id part as it wil be automatically resolved by the runtime.
	NewOperand(OperandLabel) *Operand

	// EvalLocal is used to perform local operation on the ciphertext. This is where the FHE computation
	// is performed. The user must specify the required evaluation keys needed by the function. The provided
	// function must not call any other Runtime function (ie., it must be  strictly local circuit).
	EvalLocal(needRlk bool, galKeys []uint64, f func(he.Evaluator) error) error

	// DEC performes the decryption of in, with private output to rec.
	// The decrypted operand is considered an output for the this circuit and the
	// given reciever.
	// It expect the users to provide the decryption parameters, including the level
	// at which the operation is performed and the smudging parameter.
	DEC(in Operand, rec sessions.NodeID, params map[string]string) error

	// PCKS performes the re-encryption of in to the public key of rec.
	// The the re-encrypted operand is considered an output for the this circuit and the
	// given reciever.
	// It expect the users to provide the key-switch parameters, including the level
	// at which the operation is performed and the smudging parameter.
	PCKS(in Operand, rec sessions.NodeID, params map[string]string) error

	// Logf logs a message with the given format and arguments.
	Logf(format string, args ...interface{})
}

// PublicKeyProvider is an interface for querying public encryption- and evaluation-keys.
// The setup service is a notable implementation of this interface.
type PublicKeyProvider interface {
	GetCollectivePublicKey(context.Context) (*rlwe.PublicKey, error)
	GetGaloisKey(ctx context.Context, galEl uint64) (*rlwe.GaloisKey, error)
	GetRelinearizationKey(context.Context) (*rlwe.RelinearizationKey, error)
}

// Name is a type for circuit names.
// A circuit name is a string that uniquely identifies a circuit within the framework.
// Multiple instances of the same circuit can exist within the system (see circuits.ID).
type Name string

// Signature is a type for circuit signatures.
// A circuit signature is akin to a function signature in a programming language:
// it associates the name of the circuit with a set of arguments.
type Signature struct {
	Name
	Args map[string]string
}

// String returns a string representation of the circuit signature.
func (s Signature) String() string {
	args := make([]string, 0, len(s.Args))
	for k, v := range s.Args {
		args = append(args, fmt.Sprintf("%s=%s", k, v))
	}
	return fmt.Sprintf("%s(%s)", s.Name, strings.Join(args, ", "))
}

// Clone returns a deep copy of the Signature.
func (s Signature) Clone() Signature {
	return Signature{
		Name: s.Name,
		Args: maps.Clone(s.Args),
	}
}

// Descriptor is a struct for specifying a circuit execution.
// It holds the identification information for the circuit, as well as a concrete mapping from the
// node ids in the circuit definition.
type Descriptor struct {
	Signature
	sessions.CircuitID
	NodeMapping map[string]sessions.NodeID // TODO: nil node mapping is identity mapping
	Evaluator   sessions.NodeID
}

// Clone returns a deep copy of the Descriptor.
func (d Descriptor) Clone() Descriptor {
	return Descriptor{
		Signature:   d.Signature.Clone(),
		CircuitID:   d.CircuitID,
		NodeMapping: maps.Clone(d.NodeMapping),
		Evaluator:   d.Evaluator,
	}
}

// Metadata is a type for gathering information about a circuit instance.
// It is obtained by parsing a circuit defintion (see circuits.Parse)
type Metadata struct {
	Descriptor
	InputSet, Ops, OutputSet utils.Set[OperandLabel]
	InputsFor, OutputsFor    map[sessions.NodeID]utils.Set[OperandLabel]
	KeySwitchOps             map[string]protocols.Signature
	NeedRlk                  bool
	GaloisKeys               utils.Set[uint64]
}

// Event is a type for circuit-related events.
type Event struct {
	EventType
	Descriptor
}

// EventType define the type of event (see circuits.Event)
type EventType int8

const (
	// Completed corresponds to then event of a circuit being completed.
	// It is emitted zero (failure) or one time per circuit instance.
	Completed EventType = iota
	// Started corresponds to then event of a circuit being started.
	// It is emitted once per circuit instance.
	Started
	// Executing is an event type for execution-related events.
	// This event tpe can be emitted multiple times per circuit instance,
	// for example, at each protocol Event.
	Executing
	// Failed corresponds to then event of a circuit failing to execute to completion.
	Failed
)

// Output is a type for circuit outputs. It associates the output operand with the ID of the circuit that has produced it.
type Output struct {
	sessions.CircuitID
	Operand
}

var statusToString = []string{"COMPLETED", "STARTED", "EXECUTING", "FAILED"}

func (t EventType) String() string {
	if int(t) > len(statusToString) {
		t = 0
	}
	return statusToString[t]
}

func (u Event) String() string {
	return fmt.Sprintf("%s: %s", u.EventType, u.Descriptor)
}

// IDFromProtocolDescriptor returns the circuit ID from a protocol descriptor. // TODO cleaner way than op label ?
func IDFromProtocolDescriptor(pd protocols.Descriptor) sessions.CircuitID {
	opls, has := pd.Signature.Args["op"]
	if !has {
		panic("no op argument in circuit protocol event")
	}
	opl := OperandLabel(opls)
	return opl.CircuitID()
}

// TestRuntime is an implementation of the Runtime interface for testing purposes.
// It can be initialized from the FHE parameters and circuit inputs, then passed
// to a Circuit to execute it. It encrypts the requested inputs on-the-fly, under
// a test secret-key.
// See the Runtime interface.
type TestRuntime struct {
	fheParams      sessions.FHEParameters
	inputProvider  func(OperandLabel) *rlwe.Plaintext
	outputReceiver func(Output)

	l         sync.Mutex
	sk        *rlwe.SecretKey
	keygen    *rlwe.KeyGenerator
	encryptor *rlwe.Encryptor
	evaluator he.Evaluator
	decryptor *rlwe.Decryptor
}

// NewTestRuntime creates a new TestRuntime instance with the given FHE parameters and input/output functions.
func NewTestRuntime(fheParams sessions.FHEParameters, inputProvider func(OperandLabel) *rlwe.Plaintext, outputReceiver func(Output)) *TestRuntime {
	tr := &TestRuntime{}
	tr.fheParams = fheParams
	tr.inputProvider = inputProvider
	tr.outputReceiver = outputReceiver

	tr.keygen = rlwe.NewKeyGenerator(fheParams)
	tr.sk = tr.keygen.GenSecretKeyNew()
	tr.encryptor = rlwe.NewEncryptor(fheParams, tr.sk)
	tr.evaluator = sessions.NewEvaluator(fheParams, nil)
	tr.decryptor = rlwe.NewDecryptor(fheParams, tr.sk)
	return tr
}

func (tr *TestRuntime) Parameters() sessions.FHEParameters {
	return tr.fheParams
}

func (tr *TestRuntime) Input(opl OperandLabel) *FutureOperand {
	tr.l.Lock()
	defer tr.l.Unlock()
	fop := NewFutureOperand(opl)
	pt := tr.inputProvider(opl)
	if pt == nil {
		panic(fmt.Errorf("input provider returned nil input for %s", opl))
	}
	ct, err := tr.encryptor.EncryptNew(pt)
	if err != nil {
		panic(err)
	}
	fop.Set(Operand{Ciphertext: ct, OperandLabel: opl})
	return fop
}

func (tr *TestRuntime) Load(_ OperandLabel) *Operand {
	panic("not implemented") // TODO: Implement
}

func (tr *TestRuntime) NewOperand(opl OperandLabel) *Operand {
	return &Operand{OperandLabel: opl}
}

func (tr *TestRuntime) EvalLocal(needRlk bool, galKeys []uint64, f func(he.Evaluator) error) error {

	var rlk *rlwe.RelinearizationKey
	gks := make([]*rlwe.GaloisKey, len(galKeys))

	if needRlk {
		rlk = tr.keygen.GenRelinearizationKeyNew(tr.sk)
	}
	for i, gk := range galKeys {
		gks[i] = tr.keygen.GenGaloisKeyNew(gk, tr.sk)
	}

	evks := rlwe.NewMemEvaluationKeySet(rlk, gks...)
	var ev he.Evaluator
	switch sev := tr.evaluator.(type) {
	case *bgv.Evaluator:
		ev = sev.WithKey(evks)
	case *ckks.Evaluator:
		ev = sev.WithKey(evks)
	default:
		panic("unsupported evaluator type")
	}
	return f(ev)
}

func (tr *TestRuntime) DEC(in Operand, rec sessions.NodeID, params map[string]string) error {
	tr.l.Lock()
	defer tr.l.Unlock()
	pt := tr.decryptor.DecryptNew(in.Ciphertext)
	tr.outputReceiver(Output{Operand: Operand{OperandLabel: OperandLabel(fmt.Sprintf("%s-dec", in.OperandLabel)), Ciphertext: &rlwe.Ciphertext{Element: pt.Element}}, CircuitID: "test"})
	return nil
}

func (tr *TestRuntime) PCKS(in Operand, rec sessions.NodeID, params map[string]string) error {
	panic("not implemented") // TODO: Implement
}

func (tr *TestRuntime) Logf(msg string, v ...any) {
	log.Printf("[TestRuntime] %s\n", fmt.Sprintf(msg, v...))
}

// ArgumentOfType returns the argument of the given type from the signature.
// The arguments are parsed from their string representation according to the
// `strconv` package. Numbers are assumed to be in base 10 representation.
// The function returns an error if the argument is not found or if the type
// conversion fails.
func ArgumentOfType[T any](sig Signature, argName string) (arg T, err error) {
	argStr, has := sig.Args[argName]
	if !has {
		return arg, fmt.Errorf("argument %s not found in signature %s", argName, sig)
	}

	switch any(arg).(type) {
	case string:
		return any(argStr).(T), nil
	case int:
		argInt, err := strconv.Atoi(argStr)
		return any(argInt).(T), err
	case uint64:
		argUint, err := strconv.ParseUint(argStr, 10, 64)
		return any(argUint).(T), err
	case float64:
		argFloat, err := strconv.ParseFloat(argStr, 64)
		return any(argFloat).(T), err
	case bool:
		argBool, err := strconv.ParseBool(argStr)
		return any(argBool).(T), err
	default:
		return arg, fmt.Errorf("unsupported argument type %T for argument %s", arg, argName)
	}
}

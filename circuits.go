package helium

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Circuit is a circuit definition: an evaluation function and, optionally,
// a function describing its interface for a given signature.
// If Interface is nil, the interface is derived by symbolic execution of
// the evaluation function (see Parse).
type Circuit struct {
	// Interface returns the interface of the circuit for the given signature.
	Interface func(Signature) (Interface, error)
	// Eval evaluates the circuit in the given runtime.
	Eval func(CircuitRuntime) error
}

// FromFunc returns a Circuit defined by a single evaluation function, whose
// interface (ports and required keys) is derived by symbolic execution of
// the function (see Parse).
func FromFunc(eval func(CircuitRuntime) error) Circuit {
	return Circuit{Eval: eval}
}

// Describe returns the interface of the circuit for the given signature.
func (c Circuit) Describe(sig Signature, params FHEParameters) (Interface, error) {
	if c.Eval == nil {
		return Interface{}, fmt.Errorf("circuit has no evaluation function")
	}
	if c.Interface != nil {
		itf, err := c.Interface(sig)
		if err != nil {
			return Interface{}, err
		}
		return itf, itf.Validate()
	}
	return Parse(c.Eval, sig, params)
}

// CircuitRuntime is the interface available to circuits during their evaluation.
//
// A circuit is run both for real, by the evaluator node, and symbolically, to
// derive its interface (see Parse). A circuit must hence be a deterministic
// function of its signature: it must not depend on the ciphertexts' coefficients.
type CircuitRuntime interface {
	// Descriptor returns the descriptor of the evaluated circuit.
	Descriptor() Descriptor

	// Parameters returns the FHE parameters of the session.
	Parameters() FHEParameters

	// Keys declares evaluation keys required by the circuit, in addition to the
	// ones inferred from the operations requested to the Evaluator. It is needed
	// only for keys used outside of the Evaluator interface.
	Keys(Keys)

	// Input declares an input operand provided by a party, identified by a port
	// of the form "//<party>/<name>". The party is a placeholder resolved through
	// the descriptor's node mapping.
	Input(Port) *FutureOperand

	// InputSum declares a summed input: the sum of the inputs of the given parties
	// (all the session nodes if none is given). The parties are placeholders resolved
	// through the descriptor's node mapping, and at least T of them must contribute.
	InputSum(name string, parties ...string) *FutureOperand

	// Output declares an output operand of the circuit, owned by the evaluator.
	// The circuit must set every declared output before returning.
	Output(name string) *OutputOperand

	// Evaluator returns an evaluator initialized with the circuit's keys. The
	// keys required by the operations requested to this evaluator are inferred
	// when deriving the circuit's interface.
	Evaluator() Evaluator

	// Logf logs a message with the given format and arguments.
	Logf(format string, args ...interface{})
}

// Name is a type for circuit names.
// A circuit name is a string that uniquely identifies a circuit within the framework.
// Multiple instances of the same circuit can exist within the system (see Descriptor).
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
	slices.Sort(args)
	return fmt.Sprintf("%s(%s)", s.Name, strings.Join(args, ","))
}

// Clone returns a deep copy of the Signature.
func (s Signature) Clone() Signature {
	return Signature{
		Name: s.Name,
		Args: maps.Clone(s.Args),
	}
}

// Descriptor is a complete description of a circuit evaluation: the circuit
// signature, a unique id for the evaluation, the mapping from the party
// placeholders of the circuit definition to actual nodes, and the evaluator.
type Descriptor struct {
	Signature
	CircuitID   CircuitID
	NodeMapping map[string]NodeID // nil is the identity mapping
	Evaluator   NodeID
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

// HID returns a human-readable id for the circuit evaluation.
func (d Descriptor) HID() string {
	return string(d.CircuitID)
}

// String returns a string representation of the descriptor.
func (d Descriptor) String() string {
	return fmt.Sprintf("{ID: %s, Signature: %s, Evaluator: %s, NodeMapping: %v}", d.CircuitID, d.Signature, d.Evaluator, d.NodeMapping)
}

// mapParty resolves a party placeholder to a node id.
func (d Descriptor) mapParty(party string) (NodeID, error) {
	if len(party) == 0 {
		return "", fmt.Errorf("empty party")
	}
	if d.NodeMapping == nil {
		return NodeID(party), nil
	}
	nid, has := d.NodeMapping[party]
	if !has {
		return "", fmt.Errorf("no node mapping for party %s", party)
	}
	return nid, nil
}

// Port identifies an input of a circuit definition, in the form "//<party>/<name>",
// where party is a placeholder for the node providing the input.
type Port string

// Party returns the party placeholder of the port.
func (p Port) Party() string {
	party, _, _ := p.parse()
	return party
}

// Name returns the name of the port.
func (p Port) Name() string {
	_, name, _ := p.parse()
	return name
}

func (p Port) parse() (party, name string, err error) {
	s := string(p)
	if !strings.HasPrefix(s, "//") {
		return "", "", fmt.Errorf("invalid port %q: must be of the form //<party>/<name>", p)
	}
	parts := strings.SplitN(s[2:], "/", 2)
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[1]) == 0 || strings.Contains(parts[1], "/") {
		return "", "", fmt.Errorf("invalid port %q: must be of the form //<party>/<name>", p)
	}
	return parts[0], parts[1], nil
}

// Validate returns an error if the port is not of the form "//<party>/<name>".
func (p Port) Validate() error {
	_, _, err := p.parse()
	return err
}

// SumPort identifies a summed input of a circuit definition: the sum of the
// inputs named Name of the given parties (all the session nodes if empty).
type SumPort struct {
	Name    string
	Parties []string
}

// Keys describes the evaluation keys required by a circuit.
type Keys struct {
	Rlk       bool
	GaloisEls []uint64
}

// Merge returns the union of the key requirements.
func (k Keys) Merge(other Keys) Keys {
	res := Keys{Rlk: k.Rlk || other.Rlk}
	res.GaloisEls = append(res.GaloisEls, k.GaloisEls...)
	for _, galEl := range other.GaloisEls {
		if !slices.Contains(res.GaloisEls, galEl) {
			res.GaloisEls = append(res.GaloisEls, galEl)
		}
	}
	slices.Sort(res.GaloisEls)
	return res
}

// Interface is the interface of a circuit for a given signature: its inputs,
// summed inputs, outputs and required keys.
type Interface struct {
	Inputs    []Port
	SumInputs []SumPort
	Outputs   []string
	Keys      Keys
}

// Validate checks the interface for consistency.
func (itf Interface) Validate() error {
	if len(itf.Outputs) == 0 {
		return fmt.Errorf("circuit has no output")
	}
	seenInputs := make(map[Port]struct{}, len(itf.Inputs))
	inputNames := make(map[string]struct{})
	for _, p := range itf.Inputs {
		if err := p.Validate(); err != nil {
			return err
		}
		if _, dup := seenInputs[p]; dup {
			return fmt.Errorf("duplicate input port %s", p)
		}
		seenInputs[p] = struct{}{}
		inputNames[p.Name()] = struct{}{}
	}
	seenSums := make(map[string]struct{}, len(itf.SumInputs))
	for _, sp := range itf.SumInputs {
		if len(sp.Name) == 0 || strings.Contains(sp.Name, "/") {
			return fmt.Errorf("invalid summed input name %q", sp.Name)
		}
		if _, dup := seenSums[sp.Name]; dup {
			return fmt.Errorf("duplicate summed input %s", sp.Name)
		}
		if _, clash := inputNames[sp.Name]; clash {
			return fmt.Errorf("summed input %s has the same name as an input", sp.Name)
		}
		seenSums[sp.Name] = struct{}{}
	}
	seenOutputs := make(map[string]struct{}, len(itf.Outputs))
	for _, name := range itf.Outputs {
		if len(name) == 0 || strings.Contains(name, "/") {
			return fmt.Errorf("invalid output name %q", name)
		}
		if _, dup := seenOutputs[name]; dup {
			return fmt.Errorf("duplicate output %s", name)
		}
		seenOutputs[name] = struct{}{}
	}
	return nil
}

// Metadata is the resolved instance of a circuit evaluation: the operand ids of
// its inputs and outputs, and the participating nodes, as derived from a
// descriptor and the circuit's interface.
type Metadata struct {
	Descriptor
	Interface

	// Inputs maps the expected input operand ids (at the evaluator) to their port.
	Inputs map[OperandID]Port
	// SumInputs maps each summed input to the operand ids of its contributions,
	// in the order of its parties.
	SumInputs map[string][]OperandID
	// InputsOf maps each participant to the operand ids it must provide (sorted).
	InputsOf map[NodeID][]OperandID
	// Outputs maps each output name to its operand id.
	Outputs map[string]OperandID
	// Participants is the sorted list of input-providing nodes.
	Participants []NodeID

	inputIDs map[Port]OperandID
	sumIDs   map[string]OperandID
	sumNodes map[string][]NodeID
}

// Resolve resolves the operand ids and participants of a circuit evaluation from its
// descriptor and interface. The session nodes are used for summed inputs without
// explicit parties.
func Resolve(cd Descriptor, itf Interface, sessionNodes []NodeID) (*Metadata, error) {
	if err := itf.Validate(); err != nil {
		return nil, fmt.Errorf("invalid interface: %w", err)
	}
	if len(cd.CircuitID) == 0 {
		return nil, fmt.Errorf("circuit descriptor has no id")
	}
	if strings.Contains(string(cd.CircuitID), "/") {
		return nil, fmt.Errorf("invalid circuit id %q", cd.CircuitID)
	}
	if len(cd.Evaluator) == 0 {
		return nil, fmt.Errorf("circuit descriptor has no evaluator")
	}

	md := &Metadata{
		Descriptor: cd,
		Interface:  itf,
		Inputs:     make(map[OperandID]Port, len(itf.Inputs)),
		SumInputs:  make(map[string][]OperandID, len(itf.SumInputs)),
		InputsOf:   make(map[NodeID][]OperandID),
		Outputs:    make(map[string]OperandID, len(itf.Outputs)),
		inputIDs:   make(map[Port]OperandID, len(itf.Inputs)),
		sumIDs:     make(map[string]OperandID, len(itf.SumInputs)),
		sumNodes:   make(map[string][]NodeID, len(itf.SumInputs)),
	}

	addInput := func(nid NodeID, id OperandID) error {
		if _, dup := md.Inputs[id]; dup {
			return fmt.Errorf("duplicate input operand %s", id)
		}
		md.InputsOf[nid] = append(md.InputsOf[nid], id)
		return nil
	}

	for _, p := range itf.Inputs {
		nid, err := cd.mapParty(p.Party())
		if err != nil {
			return nil, fmt.Errorf("input %s: %w", p, err)
		}
		id := NewOperandID(nid, cd.CircuitID, p.Name())
		if err := addInput(nid, id); err != nil {
			return nil, err
		}
		md.Inputs[id] = p
		md.inputIDs[p] = id
	}

	for _, sp := range itf.SumInputs {
		var nids []NodeID
		if len(sp.Parties) == 0 {
			nids = slices.Clone(sessionNodes)
		} else {
			for _, party := range sp.Parties {
				nid, err := cd.mapParty(party)
				if err != nil {
					return nil, fmt.Errorf("summed input %s: %w", sp.Name, err)
				}
				nids = append(nids, nid)
			}
		}
		if len(nids) == 0 {
			return nil, fmt.Errorf("summed input %s has no contributing party", sp.Name)
		}
		slices.Sort(nids)
		ids := make([]OperandID, 0, len(nids))
		for _, nid := range nids {
			id := NewOperandID(nid, cd.CircuitID, sp.Name)
			if err := addInput(nid, id); err != nil {
				return nil, err
			}
			ids = append(ids, id)
		}
		md.SumInputs[sp.Name] = ids
		md.sumIDs[sp.Name] = NewOperandID(cd.Evaluator, cd.CircuitID, sp.Name)
		md.sumNodes[sp.Name] = nids
	}

	for _, name := range itf.Outputs {
		md.Outputs[name] = NewOperandID(cd.Evaluator, cd.CircuitID, name)
	}

	for nid, ids := range md.InputsOf {
		slices.Sort(ids)
		md.InputsOf[nid] = ids
		md.Participants = append(md.Participants, nid)
	}
	slices.Sort(md.Participants)

	return md, nil
}

// InputID returns the operand id of the given input port.
func (md *Metadata) InputID(p Port) (OperandID, bool) {
	id, has := md.inputIDs[p]
	return id, has
}

// SumID returns the operand id of the given summed input (owned by the evaluator).
func (md *Metadata) SumID(name string) (OperandID, bool) {
	id, has := md.sumIDs[name]
	return id, has
}

// SumNodes returns the nodes contributing to the given summed input.
func (md *Metadata) SumNodes(name string) []NodeID {
	return md.sumNodes[name]
}

// ExpectedInputs returns the sorted operand ids the evaluator expects to receive.
func (md *Metadata) ExpectedInputs() []OperandID {
	ids := make([]OperandID, 0, len(md.Inputs))
	for id := range md.Inputs {
		ids = append(ids, id)
	}
	for _, sumIDs := range md.SumInputs {
		ids = append(ids, sumIDs...)
	}
	slices.Sort(ids)
	return ids
}

// IsParticipant returns whether nid provides inputs to the circuit.
func (md *Metadata) IsParticipant(nid NodeID) bool {
	_, has := md.InputsOf[nid]
	return has
}

// IsEvaluator returns whether nid is the evaluator of the circuit.
func (md *Metadata) IsEvaluator(nid NodeID) bool {
	return md.Evaluator == nid
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

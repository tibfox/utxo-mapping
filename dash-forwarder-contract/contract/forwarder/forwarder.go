// Package forwarder is the core of the dash-forwarder-contract. It owns
// the execute() logic that the dash-mapping-contract invokes after
// crediting an op=call IS deposit.
//
// Hard invariants enforced here (security-critical):
//
//  1. Only the configured dash-mapping-contract may call execute(). Any
//     other caller is rejected. This is the linchpin of the contract —
//     compromise of this check means anyone could spoof effectiveCaller.
//  2. The forwarder NEVER mutates the mapped-DASH ledger. It only invokes
//     call_as on the target. All ledger changes happen in mapping.
//  3. The forwarder reads forwardQueue from the mapping contract via
//     contracts.read. It trusts whatever mapping wrote there because
//     mapping is the only entity that COULD write it.
package forwarder

import (
	"encoding/base64"
	"strings"

	"dash-forwarder-contract/contract/constants"
	ce "dash-forwarder-contract/contract/contracterrors"
	"dash-forwarder-contract/sdk"
)

// ForwardQueueEntry is the state shape dash-mapping-contract writes to
// forwardQueue[txid]. Encoded as a simple delimited string for now —
// the parser handles legacy/tinyjson schema once mapping contract
// formalises it in workstream 5. Format:
//
//	sender|instruction|callFunding|status
//
// (Mapping contract MUST emit this exact format until both sides switch
// together to tinyjson.)
type ForwardQueueEntry struct {
	Sender      string // DashDID — the user the call is "from"
	Instruction string // canonical op=call;... string
	CallFunding int64  // duffs being routed to target (0 for value-less)
	Status      string // one of constants.Status* values
}

// Execute is the contract's only externally-callable action. Logic
// follows spec §5.3 with concrete steps numbered.
func Execute(txid string) error {
	// Step 1: hard-check caller. This is the most security-critical
	// line in this contract.
	mappingId := sdk.StateGetObject(constants.DashMappingContractIdStateKey)
	if mappingId == nil || *mappingId == "" {
		return ce.NewError(ce.ErrInitialization,
			"dash-forwarder-contract not initialised: mapping contract id missing")
	}
	caller := sdk.GetEnv().Caller.String()
	expected := "contract:" + *mappingId
	if caller != expected {
		return ce.NewError(ce.ErrNoPermission,
			"forwarder.execute called by "+caller+", expected "+expected)
	}

	// Step 2: read forwardQueue entry from mapping contract state.
	entryKey := constants.ForwardQueueKeyPrefix + txid
	entryRaw := sdk.ContractStateGet(*mappingId, entryKey)
	if entryRaw == nil || *entryRaw == "" {
		return ce.NewError(ce.ErrStateAccess,
			"forwardQueue[txid] not found in mapping state: "+txid)
	}

	entry, err := parseForwardQueueEntry(*entryRaw)
	if err != nil {
		return ce.NewError(ce.ErrInput,
			"could not parse forwardQueue entry: "+err.Error())
	}

	// Step 3: verify status.
	if entry.Status != constants.StatusPendingForward {
		return ce.NewError(ce.ErrInput,
			"forwardQueue entry status is "+entry.Status+", expected "+constants.StatusPendingForward)
	}

	// Step 4: parse instruction → (target, method, args).
	parsed, err := ParseInstruction(entry.Instruction)
	if err != nil {
		return ce.NewError(ce.ErrInput, "could not parse instruction: "+err.Error())
	}
	if parsed.Op != constants.OpCallValue {
		return ce.NewError(ce.ErrInput,
			"forwarder.execute called for non-call op="+parsed.Op)
	}

	// Step 5: verify target is in mapping's allowedTargets list.
	allowedKey := constants.AllowedTargetsKeyPrefix + parsed.Target
	allowed := sdk.ContractStateGet(*mappingId, allowedKey)
	if allowed == nil || *allowed != "1" {
		return ce.NewError(ce.ErrNoPermission,
			"target "+parsed.Target+" is not in mapping's allowedTargets list")
	}

	// Step 6: invoke call_as. The target sees:
	//   msg.caller          = "contract:<dash-forwarder-contract.id>"
	//   msg.effective_caller = entry.Sender (the DashDID)
	//
	// Per the spec §5.4, effectiveCaller is per-call-frame; if the
	// target makes its own contract calls downstream, the grandchild
	// sees the target as both caller and effectiveCaller. User
	// identity propagates downstream only via explicit args.
	//
	// Decode ArgsB64 → raw bytes before invoking the target. Per spec
	// §5.2.1 the on-wire args field is base64-encoded so the instruction
	// grammar (`;`-separated KVs, `=`-separated field/value) stays
	// unambiguous regardless of payload content. The target contract
	// expects the DECODED payload — JSON for swap-like surfaces,
	// "key,value" for the call-tss test fixture. Without this decode
	// the target's input is the raw base64 string and any parse step
	// silently fails (returns "invalid input" but with result!=nil,
	// so the forwarder reports a false-positive success).
	decodedArgs, b64err := DecodeArgs(parsed.ArgsB64)
	if b64err != nil {
		return ce.NewError(ce.ErrInput,
			"args= field not valid base64: "+b64err.Error())
	}
	result := sdk.ContractCallAs(parsed.Target, parsed.Method, decodedArgs, entry.Sender, &sdk.ContractCallOptions{})
	// Audit M12 (5.5): the previous nil-only check let an aborted
	// target return propagate as success — the dispatcher would then
	// mark the forwardQueue FORWARDED and consume the RC budget even
	// though the user-visible target state didn't change. Mirror the
	// mapping's mapInstantSendV2:310 check (result==nil OR ABORT:
	// prefix) so a non-nil but failed call is properly surfaced as
	// transaction failure → caller's forwardQueue is FORWARD_FAILED
	// + the HBD reimbursement is refunded.
	if result == nil || isAbortResult(*result) {
		msg := "target call failed"
		if result != nil {
			msg = msg + ": " + *result
		}
		return ce.NewError(ce.ErrTransaction, msg)
	}
	return nil
}

// isAbortResult detects target failure from a non-nil call return.
// Mirrors dash-mapping-contract/contract/mapping/mapinstantsend_v2.go:342.
// Contracts using the SDK abort path return a string starting with
// "ABORT:" + the error message; treating those as success was the
// audit M12 misreport.
func isAbortResult(result string) bool {
	return len(result) >= 6 && result[:6] == "ABORT:"
}

// ParsedInstruction is the structured form of an op=call instruction.
type ParsedInstruction struct {
	Op       string // always "call" for forwarder-invoked entries
	Target   string // contract: prefix, e.g. "vsc1DexRouter"
	Method   string
	ArgsB64  string
	Sid      string
	AmountDuffs int64 // 0 for value-less calls
}

// ParseInstruction unpacks the canonical "op=...;contract=...;..." string.
// Exported for the test suite and (eventually) for the mapping contract
// to validate that the instruction it baked into the deposit address
// re-parses cleanly before scheduling a forward.
func ParseInstruction(instruction string) (ParsedInstruction, error) {
	var out ParsedInstruction
	if instruction == "" {
		return out, ce.NewError(ce.ErrInput, "instruction empty")
	}

	fields := strings.Split(instruction, constants.InstructionFieldDelimiter)
	for _, f := range fields {
		idx := strings.Index(f, constants.InstructionKVDelimiter)
		if idx < 0 {
			return out, ce.NewError(ce.ErrInput, "instruction field missing delimiter: "+f)
		}
		key := f[:idx]
		val := f[idx+1:]
		switch key {
		case constants.InstructionOpKey:
			out.Op = val
		case constants.InstructionContractKey:
			out.Target = val
		case constants.InstructionMethodKey:
			out.Method = val
		case constants.InstructionArgsKey:
			out.ArgsB64 = val
		case constants.InstructionSidKey:
			out.Sid = val
		case constants.InstructionAmountKey:
			n, perr := parseInt64(val)
			if perr != nil {
				return out, ce.NewError(ce.ErrInput, "invalid amount: "+val)
			}
			out.AmountDuffs = n
		// Unknown keys are ignored on purpose — forwards-compatible parsing.
		}
	}

	if out.Op == "" {
		return out, ce.NewError(ce.ErrInput, "instruction missing op=")
	}
	if out.Op == constants.OpCallValue {
		if out.Target == "" || out.Method == "" {
			return out, ce.NewError(ce.ErrInput, "op=call requires contract= and method=")
		}
	}
	if out.Sid == "" {
		return out, ce.NewError(ce.ErrInput, "instruction missing sid=")
	}
	return out, nil
}

// parseForwardQueueEntry decodes the pipe-delimited entry. Replace with
// tinyjson when workstream 5 settles on a schema; this string format is
// only for the v1 boostrap.
func parseForwardQueueEntry(raw string) (ForwardQueueEntry, error) {
	parts := strings.SplitN(raw, "|", 4)
	if len(parts) != 4 {
		return ForwardQueueEntry{}, ce.NewError(ce.ErrInput,
			"forwardQueue entry must have 4 fields separated by '|', got "+intToString(len(parts)))
	}
	callFunding, err := parseInt64(parts[2])
	if err != nil {
		return ForwardQueueEntry{}, ce.NewError(ce.ErrInput, "invalid callFunding: "+parts[2])
	}
	return ForwardQueueEntry{
		Sender:      parts[0],
		Instruction: parts[1],
		CallFunding: callFunding,
		Status:      parts[3],
	}, nil
}

// SerializeForwardQueueEntry is the inverse of parseForwardQueueEntry —
// used by tests (and once workstream 5 lands, by the mapping contract).
func SerializeForwardQueueEntry(e ForwardQueueEntry) string {
	return e.Sender + "|" + e.Instruction + "|" + intToString(int(e.CallFunding)) + "|" + e.Status
}

// ===== helpers (no strconv to keep WASM build tight) =====

// parseInt64 parses a decimal int64 from a string.
//
// Audit L7: the previous implementation built `n` via plain `n*10 +
// digit` with no overflow check. A 20-digit input (e.g. 19 nines or
// MaxInt64+1 = 9223372036854775808) wrapped silently into a negative
// or near-zero int64 and could land in CallFunding / amount fields
// downstream. Mirror the standard-library strconv.ParseInt overflow
// behaviour (return error before the wrap).
func parseInt64(s string) (int64, error) {
	if s == "" {
		return 0, ce.NewError(ce.ErrInput, "empty number")
	}
	neg := false
	i := 0
	if s[0] == '-' {
		neg = true
		i = 1
		if len(s) == 1 {
			return 0, ce.NewError(ce.ErrInput, "lone minus sign")
		}
	}
	const maxInt64 = int64(9223372036854775807)
	const cutoff = maxInt64 / 10
	const cutoffDigit = uint8(maxInt64 % 10)
	var n int64
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, ce.NewError(ce.ErrInput, "non-digit in number: "+s)
		}
		d := c - '0'
		// Audit L7: detect overflow BEFORE the multiply/add that would
		// wrap. n > cutoff means n*10 would overflow; n == cutoff and
		// d > cutoffDigit means n*10+d would overflow into the negative
		// (positive int64 max is 9223372036854775807).
		if n > cutoff || (n == cutoff && d > cutoffDigit) {
			return 0, ce.NewError(ce.ErrInput, "number overflows int64: "+s)
		}
		n = n*10 + int64(d)
	}
	if neg {
		n = -n
	}
	return n, nil
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// DecodeArgs base64-decodes the args= field from a parsed op=call
// instruction. Empty input returns ("", nil) — value-less calls with
// no payload (e.g. nft-mint with no parameters) are legitimate and
// just pass an empty string to the target. Exported for unit tests.
func DecodeArgs(argsB64 string) (string, error) {
	if argsB64 == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(argsB64)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

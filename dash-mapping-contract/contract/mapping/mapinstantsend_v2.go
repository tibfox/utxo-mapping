// HandleMapInstantSendV2 — the lazy-attestation fast-path entry point.
// See forwarder_integration.go for the helpers + types this consumes.
//
// Spec §5.2.3 sequence, implemented end-to-end:
//
//  1. Re-derive D from instruction; verify D appears as a destination in rawTxHex.
//  2. Verify BLS aggregate attestation against at-epoch validator set.
//  3. Resolve sender DashDID (strict same-address-all-inputs rule, §5.2.5).
//  4. Apply amount-matching rules (§5.2.4).
//  5. Per-DashDID rate-limit check (§5.2.7).
//  6. Credit DashDID(sender) internal DASH balance.
//  7. Mark IS-lock as processed (idempotency).
//  8. Op-specific path:
//     - op=auth: done (subsidised — no RC reimbursement)
//     - op=call: write forwardQueue + invoke forwarder + RC reimbursement
package mapping

import (
	"crypto/sha256"
	"dash-mapping-contract/contract/constants"
	ce "dash-mapping-contract/contract/contracterrors"
	"dash-mapping-contract/sdk"
	"encoding/hex"
	"strconv"
)

// HandleMapInstantSendV2 is the main entry into the fast-path mapping flow.
// All state mutations happen in-place on ms; caller (main.go) calls
// SaveToState afterwards.
//
// Returns nil on success, or a tagged ContractError on rejection. Most
// rejection paths leave state untouched, so caller can revert cleanly.
// The op=call forward path is the one place where partial state changes
// can persist (credit happens, forward may fail) — those paths
// explicitly mark forwardQueue status so the result is auditable.
func (ms *MappingState) HandleMapInstantSendV2(params MapInstantSendV2ParamsFull) error {
	body := &params.Body
	agg := &params.Agg

	// ===== Step 1: re-derive D and verify it's an output in rawTxHex =====

	// Derive the expected deposit address from the supplied instruction
	// using the bridge pubkeys we hold in state. Any mismatch from what
	// the user actually paid to is fatal — the attestation can't bind
	// us to crediting a different address.
	primaryHex := hex.EncodeToString(ms.PublicKeys.Primary[:])
	backupHex := hex.EncodeToString(ms.PublicKeys.Backup[:])
	D, _, err := DepositAddress(primaryHex, backupHex, body.Instruction, ms.NetworkParams)
	if err != nil {
		return ce.NewContractError(ce.ErrInput, "deposit address derivation failed: "+err.Error())
	}

	paidAmount, vout, err := FindOutputAmountAndIndex(body.RawTxHex, D, ms.NetworkParams)
	if err != nil {
		return ce.NewContractError(ce.ErrInput, "could not parse tx outputs: "+err.Error())
	}
	if paidAmount == 0 {
		return ce.NewContractError(ce.ErrInput,
			"derived deposit address "+D+" not found in tx outputs (mismatched instruction?)")
	}

	// ===== Step 1.5: idempotency short-circuit BEFORE crypto + state writes =====
	//
	// Audit FD3-1 (HIGH 8.0): idempotency now keys on `txid:vout` so
	// both the fast path and the slow `map` action's per-output credit
	// can detect "already processed" against the SAME marker. The
	// txid is deterministic from rawTxBytes (sha256d, byte-reversed
	// for display). vout is the position of the FIRST output paying
	// to the derived deposit address.
	//
	// Fixes earlier audits `mapv2-expensive-before-idempotency` and
	// `rate-limit-bumped-before-idempotency-check`: replays must
	// short-circuit before BLS verify (which burns crypto gas) and
	// before checkAndBumpRateLimit (which would grief the victim's
	// rate-limit budget).
	txid := rawTxId(body.RawTxHex)
	if isAlreadyProcessedV2(txid, vout) {
		return nil
	}

	// ===== Step 1.6: SPV inclusion proof verify (audit C2 CRIT 9.1) =====
	//
	// The fast path previously trusted the submitter-supplied rawTxHex
	// without ever asking dashd whether the tx was mined or even existed.
	// A BLS quorum signing over a fabricated rawTx then minted wrapped
	// DASH from a tx that never existed. Require the same inclusion
	// proof shape the slow path uses (VerificationRequest) so the
	// credit only fires after the tx is proven in a confirmed block.
	//
	// We don't enforce a minimum confirmation depth here — that's the
	// oracle's responsibility (it only chain-relays headers after
	// sufficient confirmations; see CLAUDE.md § Security Model).
	rawTxBytes, decErr := hex.DecodeString(body.RawTxHex)
	if decErr != nil {
		return ce.NewContractError(ce.ErrInput, "raw tx not hex: "+decErr.Error())
	}
	spvReq := &VerificationRequest{
		BlockHeight:    body.BlockHeight,
		RawTxHex:       body.RawTxHex,
		MerkleProofHex: body.MerkleProofHex,
		TxIndex:        body.TxIndex,
	}
	if err := verifyTransaction(spvReq, rawTxBytes); err != nil {
		return ce.Prepend(err, "fast-path SPV verify failed")
	}

	// ===== Step 2: verify BLS aggregate attestation =====

	// Build the canonical signed message exactly as validators did.
	chainID := body.ChainId
	if chainID == "" {
		return ce.NewContractError(ce.ErrInput, "chainId must be set in params")
	}
	msg, err := CanonicalAttestationMessage(chainID, body.Epoch, body.RawTxHex, body.Instruction)
	if err != nil {
		return ce.WrapContractError(ce.ErrInput, err, "canonical message build failed")
	}

	// Aggregate pubkeys for the contract-side verification. The
	// crypto.bls_verify_aggregate host fn does the AggregatePubkeys
	// internally — we just concatenate hex.
	if len(body.Attestations) == 0 {
		return ce.NewContractError(ce.ErrInput, "no attestations provided")
	}

	// Validator-set membership check: every attesting DID must be in
	// the registered validator set at body.Epoch (with a one-epoch
	// grace window for rotations — see verifyAttestationsAgainstValidatorSet).
	// Pubkeys in the attestation MUST match the registered pubkey for
	// the same DID, defending against an aggregator that provides a
	// stale-but-valid signature against an unrelated pubkey.
	recognised, err := verifyAttestationsAgainstValidatorSet(body.Attestations, body.Epoch)
	if err != nil {
		return ce.Prepend(err, "validator-set check failed")
	}

	// N-of-M quorum check. Threshold is admin-configurable via
	// setMinAttestations. Default 1 (devnet bring-up); production
	// raises to 2M/3+1 of the active set.
	threshold := minAttestationsRequired()
	if recognised < threshold {
		return ce.NewContractError(ce.ErrNoPermission,
			"attestation quorum not met: have "+strconv.Itoa(recognised)+
				", need "+strconv.Itoa(threshold))
	}

	var pubkeysHexBuilder []byte
	for _, a := range body.Attestations {
		if len(a.PubkeyHex) != 96 {
			return ce.NewContractError(ce.ErrInput,
				"validator pubkey must be 48 bytes (96 hex chars), got "+a.PubkeyHex)
		}
		pubkeysHexBuilder = append(pubkeysHexBuilder, []byte(a.PubkeyHex)...)
	}
	pubkeysHex := string(pubkeysHexBuilder)

	if !sdk.VerifyBlsAggregate(pubkeysHex, hex.EncodeToString(msg), agg.AggSigHex) {
		return ce.NewContractError(ce.ErrNoPermission,
			"BLS attestation aggregate failed to verify against signed message")
	}

	// ===== Step 3: resolve sender DashDID =====

	dashGenesisCAIP2Hex := ms.dashGenesisCAIP2Hex() // mainnet/testnet selector
	senderDID, err := ResolveSenderDashDID(body.RawTxHex, dashGenesisCAIP2Hex, ms.NetworkParams)
	if err != nil {
		return ce.Prepend(err, "could not resolve sender DashDID")
	}

	// ===== Step 4: amount-matching rules =====

	parsed, err := ParseInstructionV2(body.Instruction)
	if err != nil {
		return ce.Prepend(err, "instruction parse failed")
	}

	// Per spec §5.2.4 dust floor: anything below MinDustDuffs is rejected
	// (network-fee dominates the credit — no economic point in processing).
	if paidAmount < constants.MinDustDuffs {
		return ce.NewContractError(ce.ErrInput,
			"amount below dust threshold")
	}
	// For value-bearing op=call, declared amount must also be above the
	// 0.01 DASH floor. Below that, attacker spam becomes uneconomic per
	// §5.2.7.
	if parsed.Op == constants.OpCallValue && parsed.AmountDuffs > 0 &&
		parsed.AmountDuffs < constants.MinCallFundingDuffs {
		return ce.NewContractError(ce.ErrInput,
			"op=call amount below 0.01 DASH floor (§5.2.7)")
	}

	// ===== Step 5: per-DashDID rate-limit check =====

	// "now" is approximated as the env's block height — sufficient for the
	// sliding-window check since the window is in seconds and block-height
	// monotonicity is enough. Real implementations might multiply by Magi's
	// typical block time or read env.BlockTimestamp.
	now := sdk.GetEnv().BlockHeight
	withinLimit := checkAndBumpRateLimit(senderDID, now)

	// ===== Step 6: register UTXO + bump Supply (audit H1 HIGH 7.8) =====
	//
	// Previously the fast path only credited a-<did> without registering
	// the underlying UTXO or bumping the protocol Supply ledger → unmap
	// would drain real UTXOs that other users had deposited via the slow
	// path. Mirror the slow path's MapDeposit case (mapping.go:159-164,
	// 302-321) — register the proven UTXO into ms.UtxoList + bump
	// Supply.{ActiveSupply,UserSupply}.
	utxoInternalId, allocErr := ms.allocateConfirmedId()
	if allocErr != nil {
		return allocErr
	}
	ms.UtxoList = append(ms.UtxoList, UtxoRegistryEntry{Id: utxoInternalId, Amount: paidAmount})
	// Build the Utxo record (TxId is the rawTx's sha256d hex, Vout is
	// the deposit-address index found at Step 1).
	depositUtxo := Utxo{
		TxId:   txid,
		Vout:   vout,
		Amount: paidAmount,
		// PkScript + Tag aren't required for the fast-path credit; the
		// slow path populates them when it processes the same tx via a
		// full block sweep. Leaving them zero here means the unmap path
		// will need the slow-path block-walk to enrich them before the
		// UTXO can be spent — that's fine because unmap relies on a
		// confirmed-status promotion that the slow path drives.
	}
	saveUtxo(utxoInternalId, &depositUtxo)
	newActive, sErr := safeAdd64(ms.Supply.ActiveSupply, paidAmount)
	if sErr != nil {
		return ce.WrapContractError(ce.ErrArithmetic, sErr, "supply.active overflow")
	}
	ms.Supply.ActiveSupply = newActive
	newUser, sErr := safeAdd64(ms.Supply.UserSupply, paidAmount)
	if sErr != nil {
		return ce.WrapContractError(ce.ErrArithmetic, sErr, "supply.user overflow")
	}
	ms.Supply.UserSupply = newUser

	// ===== Step 7: credit + canonical idempotency marker =====
	// (idempotency-already-processed check ran at Step 1.5 above.)

	if err := incInternalBalance(senderDID, "dash", paidAmount); err != nil {
		return err
	}
	// Audit FD3-1: write the canonical txid:vout marker (checked by
	// both fast + slow paths) instead of the legacy per-tx marker.
	// The legacy markAsProcessed call has been removed — the per-txid
	// "p2-<txid>" key is superseded by the more-precise
	// "m-<txid>-<vout>" key.
	markAsProcessedV2(txid, vout)

	// ===== Step 8: op-specific path =====

	switch parsed.Op {
	case constants.OpAuthValue:
		// Login. Credit-only, subsidised. No forward dispatch.
		//
		// Audit M18 (MED 5.0): the previous code unconditionally
		// subsidised the op=auth login. An attacker spawning fresh
		// DashDIDs (cost: gas for the deposit address derive) could
		// drain the operator's HBD subsidy pool. Apply the same
		// rate-limit gate to op=auth — RATE_LIMITED logins still
		// credit the DASH but stop counting against the subsidy
		// surface. Same RC-budget cap the §5.2.6 dispatchForward
		// uses, but charged against a separate "auth-subsidy" key
		// (op=auth has no callFunding to absorb the cost).
		if !withinLimit {
			saveForwardQueueEntry(rawTxId(body.RawTxHex), ForwardQueueEntry{
				Sender:      senderDID,
				Instruction: body.Instruction,
				CallFunding: 0,
				Status:      "RATE_LIMITED",
			})
		}
		return nil

	case constants.OpCallValue:
		if !withinLimit {
			// Spec §5.2.7: over rate-limit, contract credits but skips
			// forward. forwardQueue gets a "rate-limited" status so
			// auditors can see what happened.
			saveForwardQueueEntry(rawTxId(body.RawTxHex), ForwardQueueEntry{
				Sender:      senderDID,
				Instruction: body.Instruction,
				CallFunding: 0,
				Status:      "RATE_LIMITED",
			})
			return nil
		}
		return ms.dispatchForward(senderDID, parsed, paidAmount, body.RawTxHex)

	default:
		return ce.NewContractError(ce.ErrInput,
			"unknown op="+parsed.Op)
	}
}

// dispatchForward performs the §5.2.3 steps 4-9: pre-check HBD reserves,
// debit user, credit target, write forwardQueue, call forwarder.execute,
// on success deduct the RC reimbursement HBD, on failure (forwarder
// abort) refund the target → sender.
//
// CRITICAL ORDERING (audit `post-forward-rc-rollback-drains-target`):
// the HBD pre-check runs BEFORE the forwarder is invoked. The previous
// order — invoke forwarder, then check HBD, then roll back if short —
// allowed an allow-listed target with any internal-transfer surface to
// pocket callFunding while the rollback's silently-swallowed
// decInternalBalance error left the sender double-credited (phantom
// DASH mint). Never roll back ledger state after a successful external
// call.
func (ms *MappingState) dispatchForward(
	senderDID string,
	parsed ParsedInstruction,
	paidAmount int64,
	rawTxHex string,
) error {
	// callFunding = min(creditedAmount, declaredAmount), 0 = value-less
	callFunding := int64(0)
	if parsed.AmountDuffs > 0 {
		callFunding = parsed.AmountDuffs
		if callFunding > paidAmount {
			callFunding = paidAmount
		}
	}

	txid := rawTxId(rawTxHex)
	targetAddr := parsed.Target

	// Verify the target is in the allow-list (§5.2.7).
	if !isTargetAllowed(targetAddr) {
		// User keeps DASH credit; forward marked failed.
		saveForwardQueueEntry(txid, ForwardQueueEntry{
			Sender:      senderDID,
			Instruction: parsed.Op + ";" + parsed.Target, // abbreviated
			CallFunding: callFunding,
			Status:      constants.StatusForwardFailed,
		})
		return nil
	}

	// Forwarder contract id must be set (admin init).
	forwarderId := sdk.StateGetObject(constants.ForwarderContractIdStateKey)
	if forwarderId == nil || *forwarderId == "" {
		return ce.NewContractError(ce.ErrInitialization,
			"forwarder contract not configured; cannot dispatch op=call")
	}

	// ===== HBD reimbursement PRE-CHECK + DEBIT (spec §5.2.6) =====
	//
	// Compute the L2-tx RC cost upper-bound and convert via the
	// 1000 RC = 1 HBD rate (params.go:11). Deduct from sender's
	// internal HBD balance BEFORE invoking the forwarder. If
	// insufficient, mark FORWARD_FAILED_INSUFFICIENT_RC and skip
	// dispatch entirely — the user keeps their DASH credit but the
	// forward never runs. This is the only safe order: rolling back
	// after a successful external call leaks funds (see audit
	// `post-forward-rc-rollback-drains-target`).
	rcCost := estimateRcCost(parsed)
	rcReimbursementHBD := rcCost // 1 RC = 1 milli-HBD per params comment

	if err := decInternalBalance(senderDID, "hbd", rcReimbursementHBD); err != nil {
		// Insufficient HBD: skip dispatch entirely (callFunding has NOT
		// moved yet; sender keeps their DASH credit). FORWARD_FAILED_
		// INSUFFICIENT_RC tells operators / explorers the user needs
		// to fund their HBD balance (e.g. via a first DASH→HBD swap).
		saveForwardQueueEntry(txid, ForwardQueueEntry{
			Sender:      senderDID,
			Instruction: marshalInstruction(parsed),
			CallFunding: callFunding,
			Status:      constants.StatusForwardFailedInsufficientRC,
		})
		return nil
	}

	// Move callFunding from sender to target's internal balance. The
	// HBD debit above has already committed — if the DASH transfer
	// fails (which only happens if the sender's DASH balance is short
	// of callFunding, e.g. concurrent unmap drained it), refund the
	// HBD pre-debit.
	if callFunding > 0 {
		if err := decInternalBalance(senderDID, "dash", callFunding); err != nil {
			_ = incInternalBalance(senderDID, "hbd", rcReimbursementHBD)
			return err
		}
		if err := incInternalBalance("contract:"+targetAddr, "dash", callFunding); err != nil {
			// Roll back BOTH the dash dec and the hbd dec. Sender state
			// goes back to pre-dispatch.
			_ = incInternalBalance(senderDID, "dash", callFunding)
			_ = incInternalBalance(senderDID, "hbd", rcReimbursementHBD)
			return err
		}
	}

	// Write forwardQueue PENDING.
	entry := ForwardQueueEntry{
		Sender:      senderDID,
		Instruction: marshalInstruction(parsed),
		CallFunding: callFunding,
		Status:      constants.StatusPendingForward,
	}
	saveForwardQueueEntry(txid, entry)

	// Invoke forwarder.
	result := sdk.ContractCall(*forwarderId, "execute", txid, &sdk.ContractCallOptions{})
	if result == nil || isAbortResult(*result) {
		// Forwarder ABORTed. Roll back the local pre-debits (target
		// funding + HBD reimbursement). The forwarder didn't touch
		// either of these (it operated on the target only) so the
		// refunds are safe.
		if callFunding > 0 {
			_ = decInternalBalance("contract:"+targetAddr, "dash", callFunding)
			_ = incInternalBalance(senderDID, "dash", callFunding)
		}
		_ = incInternalBalance(senderDID, "hbd", rcReimbursementHBD)
		entry.Status = constants.StatusForwardFailed
		saveForwardQueueEntry(txid, entry)
		return nil
	}

	// Success. Mark FORWARDED.
	entry.Status = constants.StatusForwarded
	saveForwardQueueEntry(txid, entry)

	// User's internal HBD was already debited above (pre-check). Now
	// send the matching native HBD out of the contract's reserves to
	// the L2 submitter (the IS service that paid the RC). Keeps the
	// invariant sum(internal HBD) == contract.native.HBD.
	submitter := sdk.GetEnv().Caller
	sdk.HiveTransfer(submitter, rcReimbursementHBD, sdk.AssetHbd)

	return nil
}

// ----- helpers -----

// isAbortResult detects forwarder failure based on result string convention.
func isAbortResult(result string) bool {
	return len(result) >= 6 && result[:6] == "ABORT:"
}

// rawTxId computes the Dash txid for the given raw tx hex. Bitcoin
// convention: double-SHA256, little-endian display. For state keys we
// use the raw 32-byte hash hex-encoded (no endian flip) for consistency
// with how validators sign it.
func rawTxId(rawTxHex string) string {
	rawBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		return rawTxHex // fallback — caller catches invalid hex elsewhere
	}
	first := sha256.Sum256(rawBytes)
	second := sha256.Sum256(first[:])
	return hex.EncodeToString(second[:])
}

// isAlreadyProcessedV2 checks the canonical txid:vout idempotency
// marker. Audit FD3-1 (HIGH 8.0) + FD6-H1 (HIGH 7.8): the marker is
// shared between the fast path (mapInstantSendV2) and the slow path
// (Map → processUtxos), so a tx that lands in BOTH is credited
// exactly once. Key shape "m-<txid>-<vout>" uses the bare "-"
// delimiter to survive cross-block CID round-trips through the
// datalayer (the "/" delimiter was silently dropped on reload).
func isAlreadyProcessedV2(txid string, vout uint32) bool {
	marker := sdk.StateGetObject(canonicalProcessedKey(txid, vout))
	return marker != nil && *marker == "1"
}

func markAsProcessedV2(txid string, vout uint32) {
	sdk.StateSetObject(canonicalProcessedKey(txid, vout), "1")
}

func canonicalProcessedKey(txid string, vout uint32) string {
	return "m-" + txid + "-" + strconv.FormatUint(uint64(vout), 10)
}

// isTargetAllowed checks allowedTargets["at/<targetId>"] = "1".
func isTargetAllowed(targetId string) bool {
	v := sdk.StateGetObject(constants.AllowedTargetsKeyPrefix + targetId)
	return v != nil && *v == "1"
}

// marshalInstruction is the inverse of ParseInstructionV2. Used to
// preserve the canonical instruction string in the forwardQueue entry
// even if the parser strips/normalises tokens.
func marshalInstruction(p ParsedInstruction) string {
	out := "op=" + p.Op + ";contract=" + p.Target + ";method=" + p.Method +
		";args=" + p.ArgsB64 + ";sid=" + p.Sid
	if p.AmountDuffs > 0 {
		out += ";amount=" + strconv.FormatInt(p.AmountDuffs, 10)
	}
	return out
}

// estimateRcCost returns an HBD-equivalent (in duffs, but we treat as
// HBD millis here for accounting parity) estimate of the L2 tx cost.
// Per params.go:11 "1000 RC ≈ 1 HBD equivalent", so 1 RC = 0.001 HBD.
//
// Static upper bound from transaction-pool/utils.go:
//   - Call min: 100 RC
//   - Per-byte data: tracked separately
//
// For a typical mapInstantSendV2 (~1KB rawTx + attestations), conservative
// upper bound is ~500 RC = 0.5 HBD ≈ $0.50. Pretty steep for small ops;
// real-world RC will be much less.
func estimateRcCost(p ParsedInstruction) int64 {
	// Audit M16 (MED 4.5): the previous flat 500/200 RC charge had no
	// payload-size component. A pathological op=call with a huge
	// ArgsB64 payload (decoded on-chain, gas-metered as O(len)) was
	// reimbursed the same 500 RC as a 16-byte call → the IS submitter
	// over-paid HBD for the L2 RC out of the mapping contract's
	// reserve. Add a per-byte component anchored to the actual
	// gas-meter rate the host fns charge.
	//
	// Cost model (RC):
	//   base op=auth   = 200
	//   base op=call   = 500
	//   + 1 RC per 32 ArgsB64 bytes (rounded up — the contract's
	//     base64 decode + forwarder dispatch scales linearly with
	//     payload size; 32 bytes/RC is conservative vs. the host's
	//     ~1 RC per 16-byte hash-to-curve)
	if p.Op == constants.OpCallValue {
		base := int64(500)
		// p.ArgsB64 is already validated to be non-empty for op=call
		// at parse time; defensive guard for safety.
		argsLen := int64(len(p.ArgsB64))
		perByte := (argsLen + 31) / 32 // ceil(argsLen / 32)
		return base + perByte
	}
	return 200 // op=auth: 200 RC ≈ 0.2 HBD
}

// dashGenesisCAIP2Hex returns the appropriate Dash genesis CAIP-2 hex
// for the current network mode. Mirrors lib/dids/dash.go's prefix
// constants — keep in sync.
//
// Selection is by ScriptHashAddrID (0x10 mainnet, 0x13 testnet) which
// the init.go params functions set. This avoids string-compares on the
// Net field that aren't reliable for cloned chaincfg.Params.
func (ms *MappingState) dashGenesisCAIP2Hex() string {
	if ms.NetworkParams != nil && ms.NetworkParams.ScriptHashAddrID == 0x10 {
		return "00000ffd590b1485b3caadc19b22e637"
	}
	return "00000bafbc94add76cb75e2ec9289483" // testnet
}

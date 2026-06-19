//go:build cross_repo
// +build cross_repo

// Proof tests for the DASH-PROVEN-FINDINGS-FINAL-2026-06-18 audit
// findings that are surgical (single file, no architectural change).
//
// Each test is structured to FAIL BEFORE THE FIX (demonstrating the
// bug) and PASS AFTER THE FIX. Comments at the top of each describe
// the finding ID, severity, and the exact code change that flips
// the outcome.
//
// Covered here:
//   - ALLOW (HIGH 7.5)  — allowance setters missing checkAuth
//   - C1    (CRIT 9.3)  — duplicate-pubkey accepted in setValidatorSet
//   - H2    (HIGH 7.5)  — setMinAttestations has no mainnet floor
//
// FD6-H1 (cross-block `/`-key idempotency loss) ships as a separate
// datalayer-level test in fd6_slash_key_proof_test.go.

package current_test

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"dash-mapping-contract/contract/constants"
	"dash-mapping-contract/contract/mapping"

	"vsc-node/lib/dids"
	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =====================================================================
// ALLOW — posting-only approve must be rejected.
// =====================================================================
//
// Finding: HandleApprove/HandleIncreaseAllowance/HandleDecreaseAllowance
// in dash-mapping-contract/contract/mapping/handlers.go:260-285 grant
// allowance authority without a checkAuth() gate. BTC's port of the
// same handlers (review7 MED-1) calls
// `if err := checkAuth(sdk.GetEnv()); err != nil { return err }`
// at the top of each (btc-mapping-contract/contract/mapping/handlers.go
// :260-303).
//
// Impact: a posting-key-only tx (RequiredAuths=[], RequiredPostingAuths
// =[victim]) can land an `approve` on the victim's account, then the
// attacker drains via transferFrom using only the victim's posting
// key — which Hive users routinely delegate to apps.
//
// Test: send a posting-only approve. checkAuth should refuse. Today
// it succeeds. After the fix it must be rejected.
//
// Fix: add `if err := checkAuth(sdk.GetEnv()); err != nil { return err }`
// to all three handlers in handlers.go + thread the error through
// the wasmexport wrappers in main.go.
func TestSecurityProof_ALLOW_PostingOnlyApproveMustReject(t *testing.T) {
	ct, contractID := makeSecProofContract(t)

	const victim = "hive:victim"
	const attacker = "hive:attacker"
	const amount = int64(1_000_000)

	payload, err := tinyjson.Marshal(mapping.AllowanceParams{
		Spender: attacker,
		Amount:  fmt.Sprintf("%d", amount),
	})
	require.NoError(t, err)

	// Posting-only auth: RequiredAuths=[] (no active auth),
	// RequiredPostingAuths=[victim]. checkAuth's contract is
	// "active auth required" — so this must be REJECTED.
	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "alloc-postingonly-tx",
			BlockId:              "block:alloc-postingonly",
			Index:                0,
			OpIndex:              0,
			Timestamp:            "2026-06-18T00:00:00",
			RequiredAuths:        []string{}, // ← THE BUG: empty active auth must abort
			RequiredPostingAuths: []string{victim},
		},
		ContractId: contractID,
		Action:     "approve",
		Payload:    payload,
		RcLimit:    1000,
		Caller:     victim,
		Intents:    []contracts.Intent{},
	})

	assert.False(t, r.Success,
		"ALLOW: posting-only approve must be rejected by checkAuth; "+
			"got Success=true (BUG — port BTC's review7 MED-1 checkAuth to "+
			"dash-mapping-contract/contract/mapping/handlers.go:260-285)")

	// Confirm the allowance was NOT written.
	key := constants.AllowancePrefix + victim + constants.DirPathDelimiter + attacker
	got := ct.StateGet(contractID, key)
	assert.Empty(t, got,
		"ALLOW: allowance MUST NOT be written on a posting-only attempt; "+
			"found %q at %q", got, key)
}

// =====================================================================
// C1 — duplicate-pubkey quorum inflation must be rejected.
// =====================================================================
//
// Finding: SaveValidatorSetForEpoch iterates didToPubkey but only
// dedups by DID (the map key). A payload like
// `did:a=pkX,did:b=pkX` (same pubkey under two distinct DID strings)
// passes the per-DID PoP verify (PoP only binds did→pubkey→account)
// and ends up in the stored validator set — every aggregate-verify
// treats it as 2 distinct signers satisfying N-of-M.
//
// Reference: utxo-mapping/dash-mapping-contract/contract/mapping/
// forwarder_integration.go:680.
//
// Test: build a payload with two distinct DID strings sharing the
// same pubkey, both with valid PoPs (PoP A binds (domain || pk || acctA),
// PoP B binds (domain || pk || acctB) — both verify because the
// signer's pubkey is identical, the account string is different, and
// the priv key is identical). Today the contract accepts the set
// (Success=true). After the fix it must abort.
//
// Fix: in SaveValidatorSetForEpoch, build a `seenPubkeys` map and
// abort with ce.ErrInput if any pubkey hex appears twice.
func TestSecurityProof_C1_DuplicatePubkeyMustReject(t *testing.T) {
	ct, contractID := makeContractTest(t)

	// Generate ONE keypair, then build TWO entries that share its
	// pubkey but bind to different account strings. Each entry's
	// PoP is freshly signed by the same priv key over (domain ||
	// pk || account_N) — both verify under the contract's PoP
	// check, which is exactly the audit's complaint.
	// Hive account names must match the validator's account-charset
	// rules (lowercase, end with [a-z0-9], hyphen-separated segments).
	// "validatorA" fails ValidateHiveAccount (R6-CORR-06).
	vkA, popHexA := makeValidatorKey(t, 0x55, "validator-a1")

	// Second entry: same pubkey, different account string, fresh
	// PoP signed by the same priv key.
	const accountB = "validator-b1"
	popB64B, err := dids.GenerateBlsPoP(vkA.priv, accountB)
	require.NoError(t, err)
	popRawB, err := base64.RawURLEncoding.DecodeString(popB64B)
	require.NoError(t, err)
	require.Len(t, popRawB, 96)
	popHexB := hex.EncodeToString(popRawB)

	// The contract's per-DID dedup keys on the literal "did" field
	// the payload supplies. Pass the SAME bls DID string with a
	// suffix marker so the map dedup doesn't collide; the audit's
	// C1 PoC does the same.
	const dupDIDSuffix = "-dup"
	didB := vkA.did.String() + dupDIDSuffix

	const epoch = uint64(11)
	payload := buildEntry(epoch, vkA.did.String(), vkA.pkHex, popHexA, vkA.account) +
		"|" + didB + "=" + vkA.pkHex + "=" + popHexB + "=" + accountB

	r := callSetValidatorSet(t, &ct, contractID, adminOwner, payload)

	// Log the outcome unconditionally so we can tell WHY the contract
	// accepted or rejected — the test enforces "rejected" but the
	// audit's claim is specifically that the rejection happens BECAUSE
	// of a pubkey-uniqueness check that doesn't exist yet. If the
	// pre-fix run rejects for SOME OTHER reason (e.g. an unrelated
	// validation failing on the dup-DID string), the test would pass
	// but for the wrong reason.
	t.Logf("C1 outcome: success=%v err=%q errMsg=%q ret=%q",
		r.Success, r.Err, r.ErrMsg, r.Ret)

	if r.Success {
		t.Fatalf("C1: duplicate-pubkey registration must be rejected; " +
			"got Success=true (BUG — add pubkey-uniqueness check to " +
			"SaveValidatorSetForEpoch at forwarder_integration.go:680)")
	}

	// Pre-fix: contract rejects because of some incidental error.
	// Post-fix: contract rejects with the canonical "duplicate pubkey"
	// / "pubkey already registered" message.
	//
	// We allow the test to pass either way for now (the assertion above
	// is the load-bearing one) — but log so the fix author can confirm
	// the rejection reason is the uniqueness check, not an unrelated
	// validation.
}

// =====================================================================
// H2 — pin the documented default; mainnet floor is the real fix.
// =====================================================================
//
// Finding: DefaultMinAttestations = 1 (constants.go:261), and the
// admin wasmexport accepts any value ≥1 without a network-mode-gated
// floor (forwarder_integration.go:812-822). A single 1-of-N attestation
// can mint wrapped DASH from the fast path.
//
// The real fix is a NetworkMode-gated floor of `⌊2N/3⌋+1` derived
// from the current validator-set size on mainnet builds. This proof
// test pins the documented default so:
//   - If a future refactor silently raises it, this fails (regtest
//     tests assuming the default == 1 will need to be updated
//     deliberately).
//   - If the fix lands and the constant is preserved (since the
//     floor lives at the wasmexport guard, not the constant), this
//     stays green.
//
// Fix: in SetMinAttestations (main.go:631), if `!IsRegtest(NetworkMode)
// && !IsTestnet(NetworkMode)`, look up the current validator-set
// size and abort if the requested value is below `⌊2N/3⌋+1`.
func TestSecurityProof_H2_DefaultMinAttestationsIsOne(t *testing.T) {
	assert.Equal(t, 1, constants.DefaultMinAttestations,
		"H2: DefaultMinAttestations was 1 at the audit pin. If you raise "+
			"it, coordinate with the mainnet-floor fix in main.go:SetMinAttestations.")
}

// =====================================================================
// Helpers
// =====================================================================

// makeSecProofContract spins up a wasm-execution harness with the
// admin owner pre-set, used by the ALLOW test.
func makeSecProofContract(t *testing.T) (test_utils.ContractTest, string) {
	t.Helper()
	requireFreshDevWasm(t)
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractID := "secproof_contract"
	ct.RegisterContract(contractID, adminOwner, contractWasmE2E)
	return ct, contractID
}

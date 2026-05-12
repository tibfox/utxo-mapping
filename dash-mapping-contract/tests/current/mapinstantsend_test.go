package current_test

import (
	"bytes"
	"dash-mapping-contract/contract/constants"
	"dash-mapping-contract/contract/mapping"
	"encoding/hex"
	"fmt"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/assert"
)

// extractTxID deserializes a hex-encoded tx and returns its txid (reversed-hex form).
func extractTxID(t *testing.T, rawHex string) string {
	t.Helper()
	rawBytes, err := hex.DecodeString(rawHex)
	if err != nil {
		t.Fatalf("decode raw tx hex: %v", err)
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(rawBytes)); err != nil {
		t.Fatalf("deserialize tx: %v", err)
	}
	return tx.TxID()
}

// TestMapInstantSend exercises the full IS-locked deposit lifecycle:
//
//  1. mapInstantSend(tx)            — should succeed, credit balance, set IL marker.
//  2. mapInstantSend(same tx)       — should fail with "already claimed".
//  3. map(same tx after block conf) — should succeed, clear marker, NOT double-credit.
//
// The trust model: contract owner stands in for the oracle DID via checkOracle's
// regtest/testnet bypass. In production, only OracleAddress can invoke this action.
func TestMapInstantSend(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(10000)
	const blockHeight = uint32(100)

	fixture := buildMapFixture(t, instruction, amount, blockHeight)
	txid := extractTxID(t, fixture.RawTxHex)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	// NOTE: no BlockPrefix needed here — mapInstantSend doesn't verify a block header.

	isPayload, err := tinyjson.Marshal(mapping.MapInstantSendParams{
		RawTxHex:     fixture.RawTxHex,
		Instructions: []string{instruction},
	})
	if err != nil {
		t.Fatal("marshal IS params:", err)
	}

	// --- Call 1: mapInstantSend ---
	r1 := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "is-tx-1",
			BlockId:              "block:is-1",
			Index:                1,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:00",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "mapInstantSend",
		Payload:    isPayload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	})
	if r1.Err != "" {
		fmt.Printf("[%s] %s: %s\n", "1", r1.Err, r1.ErrMsg)
	}
	dumpLogs(t, r1.Logs)

	assert.True(t, r1.Success, "first mapInstantSend should succeed")
	assert.Equal(
		t,
		encodeBalance(t, amount),
		ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
		"balance after IS-locked credit",
	)
	assert.Equal(
		t,
		"1",
		ct.StateGet(contractId, constants.ISLockedClaimedPrefix+txid),
		"ISLockedClaimed marker should be set",
	)

	// --- Call 2: same tx via mapInstantSend → should fail ---
	r2 := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "is-tx-2",
			BlockId:              "block:is-2",
			Index:                2,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:01",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "mapInstantSend",
		Payload:    isPayload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	})
	assert.False(t, r2.Success, "second mapInstantSend on same tx must fail (already claimed)")

	// Balance must be unchanged.
	assert.Equal(
		t,
		encodeBalance(t, amount),
		ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
		"balance must not change on duplicate mapInstantSend",
	)
	assert.Equal(
		t,
		"1",
		ct.StateGet(contractId, constants.ISLockedClaimedPrefix+txid),
		"marker should still be present after duplicate call",
	)

	// --- Now seed the block header so the normal map path can verify proof. ---
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.LastHeightKey, "100")

	mapPayload, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    blockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	})
	if err != nil {
		t.Fatal("marshal map params:", err)
	}

	// --- Call 3: map for same tx after block confirms → succeed, NO double-credit, marker cleared ---
	r3 := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId:                 "map-tx-3",
			BlockId:              "block:map-3",
			Index:                3,
			OpIndex:              0,
			Timestamp:            "2025-10-14T00:00:02",
			RequiredAuths:        []string{"hive:milo-hpr"},
			RequiredPostingAuths: []string{},
		},
		ContractId: contractId,
		Action:     "map",
		Payload:    mapPayload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:milo-hpr",
	})
	if r3.Err != "" {
		fmt.Printf("[%s] %s: %s\n", "3", r3.Err, r3.ErrMsg)
	}
	dumpLogs(t, r3.Logs)
	assert.True(t, r3.Success, "map after mapInstantSend must succeed (dedup path)")

	assert.Equal(
		t,
		encodeBalance(t, amount),
		ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
		"balance must remain at single-credit value (no double credit)",
	)
	assert.Equal(
		t,
		constants.ISLockedMarkerConfirmed,
		ct.StateGet(contractId, constants.ISLockedClaimedPrefix+txid),
		"marker should upgrade from pending to confirmed after map",
	)
}

// TestMapThenMapInstantSend_AbortsDuplicate proves the defensive guard against
// the (rare but possible) ordering inversion: a tx confirms in a block and is
// processed via `map` first, then a stale ZMQ rawtxlock event arrives. The
// second call must NOT credit again.
func TestMapThenMapInstantSend_AbortsDuplicate(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	const amount = int64(10000)
	const blockHeight = uint32(100)

	fixture := buildMapFixture(t, instruction, amount, blockHeight)
	txid := extractTxID(t, fixture.RawTxHex)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.LastHeightKey, "100")
	ct.StateSet(contractId, constants.BlockPrefix+"100", decodeHex(t, fixture.BlockHeaderHex))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	mapPayload, err := tinyjson.Marshal(mapping.MapParams{
		TxData: &mapping.VerificationRequest{
			BlockHeight:    blockHeight,
			RawTxHex:       fixture.RawTxHex,
			MerkleProofHex: fixture.MerkleProofHex,
			TxIndex:        fixture.TxIndex,
		},
		Instructions: []string{instruction},
	})
	if err != nil {
		t.Fatal(err)
	}
	isPayload, err := tinyjson.Marshal(mapping.MapInstantSendParams{
		RawTxHex:     fixture.RawTxHex,
		Instructions: []string{instruction},
	})
	if err != nil {
		t.Fatal(err)
	}

	r1 := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "map-first-1", BlockId: "block:m1", Index: 1, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{"hive:milo-hpr"},
		},
		ContractId: contractId, Action: "map", Payload: mapPayload, RcLimit: 10000,
		Caller: "hive:milo-hpr",
	})
	assert.True(t, r1.Success, "first map must succeed")
	assert.Equal(
		t,
		encodeBalance(t, amount),
		ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
		"balance after map",
	)
	assert.Equal(
		t,
		constants.ISLockedMarkerConfirmed,
		ct.StateGet(contractId, constants.ISLockedClaimedPrefix+txid),
		"map must set the confirmed marker for defense",
	)

	r2 := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "stale-is-2", BlockId: "block:is2", Index: 2, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:01", RequiredAuths: []string{"hive:milo-hpr"},
		},
		ContractId: contractId, Action: "mapInstantSend", Payload: isPayload, RcLimit: 10000,
		Caller: "hive:milo-hpr",
	})
	assert.False(t, r2.Success, "stale mapInstantSend after map must abort")
	assert.Equal(
		t,
		encodeBalance(t, amount),
		ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
		"balance must remain unchanged after rejected stale IS",
	)
}

// TestMapInstantSend_NonOracleRejected proves checkOracle gating: a random
// caller cannot credit deposits via the IS-locked path.
func TestMapInstantSend_NonOracleRejected(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	fixture := buildMapFixture(t, instruction, 10000, 100)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	// Contract owner is hive:milo-hpr — NOT the caller below.
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	payload, err := tinyjson.Marshal(mapping.MapInstantSendParams{
		RawTxHex:     fixture.RawTxHex,
		Instructions: []string{instruction},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "non-oracle", BlockId: "block:no", Index: 1, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{"hive:randomguy"},
		},
		ContractId: contractId, Action: "mapInstantSend", Payload: payload, RcLimit: 10000,
		Caller: "hive:randomguy",
	})
	assert.False(t, r.Success, "non-oracle caller must be rejected")
	assert.Equal(
		t,
		"",
		ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
		"no balance should be credited on rejected call",
	)
}

// TestMapInstantSend_PausedRejected proves that the pause guard blocks the
// IS-locked path the same way it blocks normal maps.
func TestMapInstantSend_PausedRejected(t *testing.T) {
	const instruction = "deposit_to=hive:milo-hpr"
	fixture := buildMapFixture(t, instruction, 10000, 100)

	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))
	// Pause the contract.
	ct.StateSet(contractId, constants.PausedKey, "1")

	payload, err := tinyjson.Marshal(mapping.MapInstantSendParams{
		RawTxHex:     fixture.RawTxHex,
		Instructions: []string{instruction},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "paused-call", BlockId: "block:p", Index: 1, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{"hive:milo-hpr"},
		},
		ContractId: contractId, Action: "mapInstantSend", Payload: payload, RcLimit: 10000,
		Caller: "hive:milo-hpr",
	})
	assert.False(t, r.Success, "mapInstantSend on paused contract must be rejected")
	assert.Equal(
		t,
		"",
		ct.StateGet(contractId, constants.BalancePrefix+"hive:milo-hpr"),
		"no balance credited while paused",
	)
}

// TestMapInstantSend_InvalidHexRejected proves the input-validation path.
func TestMapInstantSend_InvalidHexRejected(t *testing.T) {
	ct := test_utils.NewContractTest()
	t.Cleanup(func() { ct.DataLayer.Stop() })
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:milo-hpr", ContractWasm)
	ct.StateSet(contractId, constants.SupplyKey, string(mapping.MarshalSupply(&mapping.SystemSupply{BaseFeeRate: 1})))
	ct.StateSet(contractId, constants.PrimaryPublicKeyStateKey, decodeHex(t, TestPrimaryPubKeyHex))
	ct.StateSet(contractId, constants.BackupPublicKeyStateKey, decodeHex(t, TestBackupPubKeyHex))

	payload, err := tinyjson.Marshal(mapping.MapInstantSendParams{
		RawTxHex:     "not-valid-hex-string-zzzz",
		Instructions: []string{"deposit_to=hive:milo-hpr"},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: stateEngine.TxSelf{
			TxId: "bad-hex", BlockId: "block:b", Index: 1, OpIndex: 0,
			Timestamp: "2025-10-14T00:00:00", RequiredAuths: []string{"hive:milo-hpr"},
		},
		ContractId: contractId, Action: "mapInstantSend", Payload: payload, RcLimit: 10000,
		Caller: "hive:milo-hpr",
	})
	assert.False(t, r.Success, "invalid hex must be rejected")
}

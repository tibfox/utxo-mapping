package current_test

import (
	"eth-mapping-contract/contract/blocklist"
	"eth-mapping-contract/contract/constants"
	"eth-mapping-contract/contract/mapping"
	"fmt"
	"testing"

	"vsc-node/lib/test_utils"
	"vsc-node/modules/db/vsc/contracts"
	stateEngine "vsc-node/modules/state-processing"

	"github.com/CosmWasm/tinyjson"
	"github.com/stretchr/testify/assert"

	ethMapping "eth-mapping-contract"
)

var ContractWasm = ethMapping.DevWasm

func TestUnmap(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:testuser", ContractWasm)
	ct.StateSet(contractId, mapping.BalancePrefix+"hive:testuser", "100000")
	ct.StateSet(contractId, blocklist.LastHeightKey, "1000000")
	ct.StateSet(
		contractId,
		constants.PrimaryPublicKeyStateKey,
		`0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0`,
	)

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: 50000,
		To:     "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self: *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents: []contracts.Intent{
			{
				Type: "transfer.allow",
				Args: map[string]string{
					"contract_id": contractId,
					"limit":       "100000",
					"token":       "eth",
				},
			},
		},
	})

	dumpLogs(t, r.Logs)

	if r.Err != "" {
		fmt.Printf("Error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	fmt.Println("gas used:", r.GasUsed)

	logStateDiff(t, r.StateDiff)
	fmt.Println("Return value:", r.Ret)
}

func TestUnmapInvalidAddress(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:testuser", ContractWasm)
	ct.StateSet(contractId, mapping.BalancePrefix+"hive:testuser", "100000")

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: 50000,
		To:     "not-a-valid-eth-address",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "unmap",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	assert.False(t, r.Success, "unmap with invalid ETH address should fail")
	fmt.Printf("Expected error: %s: %s\n", r.Err, r.ErrMsg)
}

func TestTransfer(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:testuser", ContractWasm)
	ct.StateSet(contractId, mapping.BalancePrefix+"hive:testuser", "100000")

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: 30000,
		To:     "hive:recipient",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:testuser",
	})

	dumpLogs(t, r.Logs)

	if r.Err != "" {
		fmt.Printf("Error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	fmt.Println("gas used:", r.GasUsed)

	logStateDiff(t, r.StateDiff)
	fmt.Println("Return value:", r.Ret)
}

func TestTransferInsufficientBalance(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:testuser", ContractWasm)
	ct.StateSet(contractId, mapping.BalancePrefix+"hive:testuser", "1000")

	payload, err := tinyjson.Marshal(mapping.TransferParams{
		Amount: 5000,
		To:     "hive:recipient",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "transfer",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
		Caller:     "hive:testuser",
	})

	assert.False(t, r.Success, "transfer with insufficient balance should fail")
	fmt.Printf("Expected error: %s: %s\n", r.Err, r.ErrMsg)
}

func TestSeedBlocks(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:testuser", ContractWasm)

	// Seed with a dummy RLP-encoded ETH header (hex)
	seedParams := blocklist.SeedBlocksParams{
		BlockHeader: "f90200a0deadbeef",
		BlockHeight: 1000000,
	}
	payload, err := tinyjson.Marshal(seedParams)
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "seedBlocks",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	dumpLogs(t, r.Logs)

	if r.Err != "" {
		fmt.Printf("Error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	fmt.Println("gas used:", r.GasUsed)
	fmt.Println("Return value:", r.Ret)

	logStateDiff(t, r.StateDiff)
}

func TestAddBlocks(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:testuser", ContractWasm)
	ct.StateSet(contractId, blocklist.LastHeightKey, "1000000")
	ct.StateSet(contractId, constants.BlockPrefix+"1000000", "f90200a0deadbeef")

	// Add 2 dummy RLP headers
	addParams := blocklist.AddBlocksParams{
		Blocks: []string{
			"f90200a0cafebabe",
			"f90200a0baadf00d",
		},
	}
	payload, err := tinyjson.Marshal(addParams)
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "addBlocks",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	dumpLogs(t, r.Logs)

	if r.Err != "" {
		fmt.Printf("Error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	fmt.Println("gas used:", r.GasUsed)
	fmt.Println("Return value:", r.Ret)

	logStateDiff(t, r.StateDiff)
}

func TestRegisterPublicKey(t *testing.T) {
	ct := test_utils.NewContractTest()
	contractId := "mapping_contract"
	ct.RegisterContract(contractId, "hive:testuser", ContractWasm)

	payload, err := tinyjson.Marshal(mapping.PublicKeys{
		PrimaryPubKey: "0242f9da15eae56fe6aca65136738905c0afdb2c4edf379e107b3b00b98c7fc9f0",
		BackupPubKey:  "03a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
	})
	if err != nil {
		t.Fatal(err)
	}

	r := ct.Call(stateEngine.TxVscCallContract{
		Self:       *basicSelf(t, "hive:testuser"),
		ContractId: contractId,
		Action:     "registerPublicKey",
		Payload:    payload,
		RcLimit:    10000,
		Intents:    []contracts.Intent{},
	})

	dumpLogs(t, r.Logs)

	if r.Err != "" {
		fmt.Printf("Error: %s: %s\n", r.Err, r.ErrMsg)
	}
	assert.True(t, r.Success)
	fmt.Println("gas used:", r.GasUsed)
	fmt.Println("Return value:", r.Ret)

	logStateDiff(t, r.StateDiff)
}

func TestAllOperations(t *testing.T) {
	t.Run("SeedBlocks", TestSeedBlocks)
	t.Run("AddBlocks", TestAddBlocks)
	t.Run("RegisterPublicKey", TestRegisterPublicKey)
	t.Run("Transfer", TestTransfer)
	t.Run("TransferInsufficientBalance", TestTransferInsufficientBalance)
	t.Run("Unmap", TestUnmap)
	t.Run("UnmapInvalidAddress", TestUnmapInvalidAddress)
}

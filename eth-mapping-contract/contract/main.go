package main

import (
	"eth-mapping-contract/contract/blocklist"
	"eth-mapping-contract/contract/constants"
	ce "eth-mapping-contract/contract/contracterrors"
	"eth-mapping-contract/contract/mapping"
	_ "eth-mapping-contract/sdk"
	"strconv"
	"strings"

	"eth-mapping-contract/sdk"

	"github.com/CosmWasm/tinyjson"
)

// passed via ldflags, will compile for testnet when set to "testnet"
var NetworkMode string

func checkAdmin() {
	var adminAddress string
	if constants.IsTestnet(NetworkMode) {
		adminAddress = *sdk.GetEnvKey("contract.owner")
	} else {
		adminAddress = constants.OracleAddress
	}
	if sdk.GetEnv().Caller.String() != sdk.GetEnv().Sender.Address.String() {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "admin actions must be performed directly by the sender"),
		)
	}
	if sdk.GetEnv().Sender.Address.String() != adminAddress {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "this action must be performed by a contract administrator"),
		)
	}
}

//go:wasmexport seedBlocks
func SeedBlocks(blockSeedInput *string) *string {
	checkAdmin()

	var seedParams blocklist.SeedBlocksParams
	err := tinyjson.Unmarshal([]byte(*blockSeedInput), &seedParams)
	if err != nil {
		ce.CustomAbort(ce.WrapContractError(ce.ErrJson, err))
	}

	newLastHeight, err := blocklist.HandleSeedBlocks(seedParams, constants.IsTestnet(NetworkMode))
	if err != nil {
		ce.CustomAbort(err)
	}

	outMsg := "last height: " + strconv.FormatUint(uint64(newLastHeight), 10)
	return &outMsg
}

//go:wasmexport addBlocks
func AddBlocks(addBlocksInput *string) *string {
	checkAdmin()

	var addBlocksObj blocklist.AddBlocksParams
	err := tinyjson.Unmarshal([]byte(*addBlocksInput), &addBlocksObj)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder
	lastHeight, added, err := blocklist.HandleAddBlocks(addBlocksObj.Blocks, NetworkMode)
	if err != nil {
		if err != blocklist.ErrorSequenceIncorrect {
			ce.CustomAbort(err)
		} else {
			resultBuilder.WriteString("error adding blocks: " + err.Error())
			resultBuilder.WriteString(", added " + strconv.FormatUint(uint64(added), 10) + " blocks, ")
		}
	}
	resultBuilder.WriteString("last height: " + strconv.FormatUint(uint64(lastHeight), 10))

	blocklist.LastHeightToState(lastHeight)

	result := resultBuilder.String()
	return &result
}

//go:wasmexport map
func Map(incomingTx *string) *string {
	var mapInstructions mapping.MapParams
	err := tinyjson.Unmarshal([]byte(*incomingTx), &mapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	// TODO: Verify ETH transaction and extract deposit amount
	// For now, this is a placeholder that will be filled in
	// when the ETH mapping bot and verification logic are implemented.

	return mapping.StrPtr("0")
}

//go:wasmexport unmap
func Unmap(tx *string) *string {
	var unmapInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &unmapInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}
	if unmapInstructions.To == "" {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, "destination address required"),
		)
	}

	err = mapping.HandleUnmap(&unmapInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

//go:wasmexport transfer
func Transfer(tx *string) *string {
	var transferInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &transferInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	err = mapping.HandleTransfer(&transferInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

//go:wasmexport transferFrom
func TransferFrom(tx *string) *string {
	var drawInstructions mapping.TransferParams
	err := tinyjson.Unmarshal([]byte(*tx), &drawInstructions)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	err = mapping.HandleTransfer(&drawInstructions)
	if err != nil {
		ce.CustomAbort(err)
	}

	return mapping.StrPtr("0")
}

//go:wasmexport registerPublicKey
func RegisterPublicKey(keyStr *string) *string {
	env := sdk.GetEnv()
	if env.Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var keys mapping.PublicKeys
	err := tinyjson.Unmarshal([]byte(*keyStr), &keys)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if keys.PrimaryPubKey != "" {
		existingPrimary := sdk.StateGetObject(constants.PrimaryPublicKeyStateKey)
		if *existingPrimary == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.PrimaryPublicKeyStateKey, keys.PrimaryPubKey)
			resultBuilder.WriteString("set primary key to: " + keys.PrimaryPubKey)
		} else {
			resultBuilder.WriteString("primary key already registered: " + *existingPrimary)
		}
	}

	if keys.BackupPubKey != "" {
		if resultBuilder.Len() > 0 {
			resultBuilder.WriteString(", ")
		}
		existingBackup := sdk.StateGetObject(constants.BackupPublicKeyStateKey)
		if *existingBackup == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.BackupPublicKeyStateKey, keys.BackupPubKey)
			resultBuilder.WriteString("set backup key to: " + keys.BackupPubKey)
		} else {
			resultBuilder.WriteString("backup key already registered: " + *existingBackup)
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}

//go:wasmexport registerRouter
func RegisterRouter(input *string) *string {
	env := sdk.GetEnv()
	if env.Sender.Address.String() != *sdk.GetEnvKey("contract.owner") {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrNoPermission, "action must be performed by the contract owner"),
		)
	}

	var router mapping.RouterContract
	err := tinyjson.Unmarshal([]byte(*input), &router)
	if err != nil {
		ce.CustomAbort(
			ce.NewContractError(ce.ErrInput, err.Error(), ce.MsgBadInput),
		)
	}

	var resultBuilder strings.Builder

	if router.ContractId != "" {
		existingPrimary := sdk.StateGetObject(constants.RouterContractIdKey)
		if *existingPrimary == "" || constants.IsTestnet(NetworkMode) {
			sdk.StateSetObject(constants.RouterContractIdKey, router.ContractId)
			resultBuilder.WriteString("set router contract ID to: " + router.ContractId)
		} else {
			resultBuilder.WriteString("router contract ID already registered: " + *existingPrimary)
		}
	}

	return mapping.StrPtr(resultBuilder.String())
}

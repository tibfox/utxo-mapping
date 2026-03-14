package mapping

import (
	ce "eth-mapping-contract/contract/contracterrors"
	"eth-mapping-contract/sdk"
)

// HandleTransfer moves funds between accounts within the contract.
func HandleTransfer(params *TransferParams) error {
	if params.Amount == 0 {
		return ce.NewContractError(ce.ErrInput, "amount must be greater than 0")
	}
	if params.To == "" {
		return ce.NewContractError(ce.ErrInput, "recipient address required")
	}

	env := sdk.GetEnv()
	sender := env.Caller.String()
	recipient := normalizeReceiver(params.To)

	senderBal := getAccBal(sender)
	if senderBal < int64(params.Amount) {
		return ce.NewContractError(ce.ErrInput, "insufficient balance for transfer")
	}

	setAccBal(sender, senderBal-int64(params.Amount))
	recipientBal := getAccBal(recipient)
	setAccBal(recipient, recipientBal+int64(params.Amount))

	return nil
}

// HandleUnmap processes a withdrawal request, debiting the user's balance.
// The actual ETH transfer is handled by the mapping bot.
func HandleUnmap(params *TransferParams) error {
	if params.Amount == 0 {
		return ce.NewContractError(ce.ErrInput, "amount must be greater than 0")
	}
	if params.To == "" {
		return ce.NewContractError(ce.ErrInput, "destination address required")
	}

	ethNet := EthNetwork{}
	if !ethNet.ValidateAddress(params.To) {
		return ce.NewContractError(ce.ErrInput, "invalid ETH address")
	}

	env := sdk.GetEnv()
	sender := env.Sender.Address.String()

	senderBal := getAccBal(sender)
	if senderBal < int64(params.Amount) {
		return ce.NewContractError(ce.ErrInput, "insufficient balance for unmap")
	}

	setAccBal(sender, senderBal-int64(params.Amount))

	return nil
}

package mapping

// MapParams is the input to the map entrypoint.
// For ETH, TxData contains the RLP-encoded transaction and Instructions
// define what to do with the deposited funds.
//
//tinyjson:json
type MapParams struct {
	TxData       string   `json:"tx_data"`
	Instructions []string `json:"instructions"`
}

// TransferParams is the input to unmap, transfer, and transferFrom entrypoints.
//
//tinyjson:json
type TransferParams struct {
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
}

// PublicKeys holds the primary and backup public keys for the contract.
//
//tinyjson:json
type PublicKeys struct {
	PrimaryPubKey string `json:"primary_pub_key"`
	BackupPubKey  string `json:"backup_pub_key"`
}

// RouterContract holds the router contract ID.
//
//tinyjson:json
type RouterContract struct {
	ContractId string `json:"contract_id"`
}

// SystemSupply tracks the supply state for the ETH mapping contract.
type SystemSupply struct {
	ActiveSupply uint64 `json:"active_supply"`
	UserSupply   uint64 `json:"user_supply"`
	FeeSupply    uint64 `json:"fee_supply"`
}

func StrPtr(s string) *string {
	return &s
}

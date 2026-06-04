package constants

const DirPathDelimiter = "-"

const TssKeyName = "main"
const RouterContractIdKey = "routerid"

// UTXO ID pool layout (uint16 ID, 65536 slots total).
// IDs 0–1023   are the unconfirmed pool (change outputs pending confirmation).
// IDs 1024–65535 are the confirmed pool (active mapped UTXOs ready to spend).
const (
	UtxoUnconfirmedPoolSize = 1024  // number of slots in the unconfirmed pool
	UtxoConfirmedPoolStart  = 1024  // first ID in the confirmed pool
	UtxoMaxId               = 65535 // max uint16
)

// MaxUtxoAmount is the maximum satoshi value for a single UTXO in the registry.
// 6 bytes (48 bits) supports up to ~2.81M BTC — far beyond any realistic deposit.
const MaxUtxoAmount int64 = (1 << 48) - 1

const BalancePrefix = "a" + DirPathDelimiter

// ObservedBlockPrefix stores the list of observed txid:vout pairs for a given
// block height. Key: "o-<height>", Value: packed 34-byte entries (32-byte txid
// + 2-byte vout BE). Pruned alongside block headers during addBlocks.
const ObservedBlockPrefix = "o" + DirPathDelimiter
const UtxoPrefix = "u" + DirPathDelimiter
const UtxoRegistryKey = "r"
const UtxoLastIdKey = "i"
const TxSpendsRegistryKey = "p"
const TxSpendsPrefix = "d" + DirPathDelimiter
const SupplyKey = "s"

const LastHeightKey = "h"
const SeedHeightKey = "sh"
const PruneFloorKey = "pf" // lowest unpruned block height, updated during pruning

// Instruction URL search param keys
const (
	DepositToKey        = "deposit_to"
	SwapAssetOut        = "swap_asset_out"
	SwapToKey           = "swap_to"
	DestinationChainKey = "destination_chain"
)

// Address Creation
const BackupCSVBlocks = 4320 // ~1 month
const TestnetBackupCSVBlocks = 2

// Logs
const (
	LogDelimiter      = "|"
	LogKeyDelimiter   = "="
	LogArrayDelimiter = ","
)

const AllowancePrefix = "q" + DirPathDelimiter

const PausedKey = "paused"     // "1" when contract is paused, absent/empty when active
const MigrateVersionKey = "mv" // current migration version (decimal string)

// LatestMigrateVersion is the newest migration version. Set this in init/seed
// so freshly deployed contracts skip all migrations.
const LatestMigrateVersion = "1"

// Old format constants (pre-migration)
const (
	OldUtxoConfirmedPoolStart = 64
)

const OracleAddress = "did:vsc:oracle:btc"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "b" + DirPathDelimiter

// MaxBaseFeeRate caps the base fee rate at 1000 sats/vbyte.
// Any rate above this is clamped during fee calculation to prevent
// overflow or unreasonable withdrawal fees from a misconfigured oracle.
const MaxBaseFeeRate int64 = 1000

// MaxBlockRetention is the number of recent block headers to keep.
// Older headers are pruned during addBlocks to prevent unbounded state growth.
// keep a week worth of headers to allow addresses to be registered after the fact
const MaxBlockRetention = 1080

// MaxPrunePerCall limits how many old headers are deleted in a single
// addBlocks invocation to keep gas usage predictable.
const MaxPrunePerCall = 50

const (
	Testnet3 string = "testnet3"
	Testnet4 string = "testnet4"
	Mainnet  string = "mainnet"
	Regtest  string = "regtest"
)

// IsTestnet is TRUE only for real testnet builds (testnet3 OR testnet4).
// Regtest is NOT a testnet — it's the throwaway harness used by devnet
// runs + `make dev` builds.
//
// Audit R16-SEC-sec3-sibling-utxo-contracts-unfixed (mirror of the
// dash-mapping-contract SEC-3 R15 fix): the old IsTestnet collapsed
// testnet3, testnet4, and regtest into one gate. Every admin-bypass
// branch (pubkey overwrite, router overwrite) became active for the
// regtest dev build too — a dev.wasm accidentally tagged for mainnet
// (or promoted out of the dev cycle) had all governance timelocks +
// overwrite refusals disabled.
//
// Split into three predicates with explicit intent; callsites in
// main.go + blocklist.go pick the tightest gate.
func IsTestnet(networkName string) bool {
	return networkName == Testnet3 || networkName == Testnet4
}

// IsRegtest is TRUE only for the regtest harness. Used by code paths
// that are test-only (overwrites that the real testnet flow should
// exercise via the same once-and-immutable model as mainnet).
func IsRegtest(networkName string) bool {
	return networkName == Regtest
}

// IsTestnetOrRegtest is the old IsTestnet behaviour — TRUE for any
// non-mainnet build. Use when the gated behaviour is admin-trusted in
// BOTH real testnet and the regtest harness (owner-as-oracle, seedBlocks
// idempotency).
func IsTestnetOrRegtest(networkName string) bool {
	return networkName == Testnet3 || networkName == Testnet4 || networkName == Regtest
}

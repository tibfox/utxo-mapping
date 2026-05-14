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

// BTC-C3 (propagated): per-Hive-block withdrawal rate limit. The
// accumulator tracks total duffs deducted by HandleUnmap within a
// single Hive L1 block; when MaxUnmapPerBlock is positive,
// HandleUnmap rejects any unmap that would push the accumulator
// above the cap. Default 1 DASH per Hive block; operators can tune
// via setMaxUnmapPerBlock. Setting 0 disables the limit.
const DefaultMaxUnmapPerBlock int64 = 100_000_000 // 1 DASH in duffs
const MaxUnmapPerBlockKey = "muxb"

// BlockUnmapAccKey stores the per-block unmap accumulator: 16 bytes
// = uint64 BE Hive block height || uint64 BE accumulated duffs.
const BlockUnmapAccKey = "buac"

// Instruction URL search param keys. Kept identical to btc-mapping-contract
// so swap callers can use the same grammar across chains (and so a router
// front-end can treat all utxo-mapping contracts uniformly).
const (
	DepositToKey        = "deposit_to"
	SwapAssetOut        = "swap_asset_out"
	SwapToKey           = "swap_to"
	DestinationChainKey = "destination_chain"
	ReturnAddressKey    = "return_address"
	ReturnNetworkKey    = "return_network"
)

// Address Creation
const BackupCSVBlocks = 17280 // ~1 month (Dash ~2.5 min blocks)
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

const OracleAddress = "did:vsc:oracle:dash"
const PrimaryPublicKeyStateKey = "pubkey"
const BackupPublicKeyStateKey = "backupkey"

const BlockPrefix = "b" + DirPathDelimiter

// ISLockedClaimedPrefix marks deposit txs that have already been credited.
// Key: "il-<txid>", value: one of ISLockedMarker* below.
//
// The marker is set by either action (mapInstantSend or map) on successful
// credit and consulted by both at the start of processing to prevent
// double-credit. Two distinct values let us tell the paths apart and keep
// the IS-locked-then-block-confirms flow correctly idempotent:
//
//   - ISLockedMarkerPending   = "1" — set by mapInstantSend before the
//     tx has confirmed in a block. The IS-lock proves finality, oracle
//     consensus gates the credit, but no block proof exists yet.
//   - ISLockedMarkerConfirmed = "2" — set by HandleMap on successful
//     credit, OR written by HandleMap as an upgrade of a pre-existing
//     "1" marker when the IS-locked tx finally confirms (no second
//     credit issued in that case).
//
// HandleMap accepts an absent marker (normal flow → set "2") or any
// non-empty marker (already credited → idempotent no-op). HandleMapInstantSend
// only accepts an absent marker; any non-empty value aborts.
//
// IS-locked deposits are credited solely on oracle consensus — the contract
// does not verify the LLMQ BLS signature itself, the same trust model that
// already applies to Dash block-header acceptance (X11 PoW skipped).
const ISLockedClaimedPrefix = "il" + DirPathDelimiter

const (
	ISLockedMarkerPending   = "1"
	ISLockedMarkerConfirmed = "2"
)

// MaxBaseFeeRate caps the base fee rate at 500 duffs/vbyte.
// Pentest finding BTC-C6 (propagated from btc-mapping-contract): the
// previous 1000 sat/vbyte ceiling only protected against int overflow
// — within that range a misbehaving or compromised oracle can drive
// fees to griefing levels. 500 duffs/vbyte still admits genuine
// extreme-market spikes while halving the oracle's griefing range.
// Dash duffs are 1 satoshi-equivalent per the same 8-decimal model,
// so the absolute economic impact is comparable to BTC. Rates above
// this are clamped during fee calculation; rates below 1 are clamped
// up to 1.
const MaxBaseFeeRate int64 = 500

// MaxBlockRetention is the number of recent block headers to keep.
// Older headers are pruned during addBlocks to prevent unbounded state growth.
// keep a week worth of headers to allow addresses to be registered after the fact
const MaxBlockRetention = 1080

// MaxPrunePerCall limits how many old headers are deleted in a single
// addBlocks invocation to keep gas usage predictable.
const MaxPrunePerCall = 50

const (
	Testnet string = "testnet"
	Mainnet string = "mainnet"
	Regtest string = "regtest"
)

func IsTestnet(networkName string) bool {
	return networkName == Testnet || networkName == Regtest
}

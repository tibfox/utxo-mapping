package mapping

import (
	"eth-mapping-contract/sdk"
	"strconv"
)

const BalancePrefix = "bal/"

// normalizeReceiver strips the "@" prefix and ensures "hive:" prefix
// for Hive usernames.
func normalizeReceiver(receiver string) string {
	if len(receiver) == 0 {
		return ""
	}
	if receiver[0] == '@' {
		receiver = receiver[1:]
	}
	if len(receiver) >= 5 && receiver[:5] == "hive:" {
		return receiver
	}
	return "hive:" + receiver
}

func getAccBal(account string) int64 {
	balStr := sdk.StateGetObject(BalancePrefix + account)
	if *balStr == "" {
		return 0
	}
	bal, err := strconv.ParseInt(*balStr, 10, 64)
	if err != nil {
		return 0
	}
	return bal
}

func setAccBal(account string, amount int64) {
	sdk.StateSetObject(BalancePrefix+account, strconv.FormatInt(amount, 10))
}

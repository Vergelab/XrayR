package newV2board_test

import (
	"os"
	"testing"

	"github.com/Vergelab/XrayR/api"
	"github.com/Vergelab/XrayR/api/newV2board"
)

func skipWithoutLivePanel(t *testing.T) {
	t.Helper()
	if os.Getenv("XRAYR_LIVE_PANEL") == "" {
		t.Skip("skipping: set XRAYR_LIVE_PANEL=1 to run against a live panel")
	}
}

func CreateClient() api.API {
	apiConfig := &api.Config{
		APIHost:  "http://localhost:9897",
		Key:      "qwertyuiopasdfghjkl",
		NodeID:   1,
		NodeType: "V2ray",
	}
	client := newV2board.New(apiConfig)
	return client
}

func TestGetV2rayNodeInfo(t *testing.T) {
	skipWithoutLivePanel(t)
	client := CreateClient()
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetSSNodeInfo(t *testing.T) {
	skipWithoutLivePanel(t)
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:668",
		Key:      "qwertyuiopasdfghjkl",
		NodeID:   1,
		NodeType: "Shadowsocks",
	}
	client := newV2board.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetTrojanNodeInfo(t *testing.T) {
	skipWithoutLivePanel(t)
	apiConfig := &api.Config{
		APIHost:  "http://127.0.0.1:668",
		Key:      "qwertyuiopasdfghjkl",
		NodeID:   1,
		NodeType: "Trojan",
	}
	client := newV2board.New(apiConfig)
	nodeInfo, err := client.GetNodeInfo()
	if err != nil {
		t.Error(err)
	}
	t.Log(nodeInfo)
}

func TestGetUserList(t *testing.T) {
	skipWithoutLivePanel(t)
	client := CreateClient()

	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}

	t.Log(userList)
}

func TestReportReportUserTraffic(t *testing.T) {
	skipWithoutLivePanel(t)
	client := CreateClient()
	userList, err := client.GetUserList()
	if err != nil {
		t.Error(err)
	}
	generalUserTraffic := make([]api.UserTraffic, len(*userList))
	for i, userInfo := range *userList {
		generalUserTraffic[i] = api.UserTraffic{
			UID:      userInfo.UID,
			Upload:   114514,
			Download: 114514,
		}
	}
	// client.Debug()
	err = client.ReportUserTraffic(&generalUserTraffic)
	if err != nil {
		t.Error(err)
	}
}

func TestGetNodeRule(t *testing.T) {
	skipWithoutLivePanel(t)
	client := CreateClient()
	client.Debug()
	ruleList, err := client.GetNodeRule()
	if err != nil {
		t.Error(err)
	}

	t.Log(ruleList)
}

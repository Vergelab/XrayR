package controller

import "github.com/Vergelab/XrayR/api"

// onlineUsersOverThreshold reports only devices whose user moved more than
// minKB kilobytes in this cycle. Users with no traffic row are left out.
// minKB is the DeviceOnlineMinTraffic setting; the panel comment says
// 大于此流量, so the comparison is strict.
func onlineUsersOverThreshold(online []api.OnlineUser, traffic []api.UserTraffic, minKB int) []api.OnlineUser {
	minBytes := int64(minKB) * 1000
	over := make(map[int]struct{}, len(traffic))
	for _, tr := range traffic {
		if tr.Upload+tr.Download > minBytes {
			over[tr.UID] = struct{}{}
		}
	}
	result := make([]api.OnlineUser, 0)
	for _, item := range online {
		if _, ok := over[item.UID]; ok {
			result = append(result, item)
		}
	}
	return result
}

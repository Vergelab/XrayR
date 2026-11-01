package controller

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Vergelab/XrayR/api"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
)

func (c *Controller) buildVmessUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		vmessAccount := &conf.VMessAccount{
			ID:       user.UUID,
			Security: "auto",
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user), // Email: InboundTag|email|uid
			Account: serial.ToTypedMessage(vmessAccount.Build()),
		}
	}
	return users
}

func (c *Controller) buildVlessUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		vlessAccount := &vless.Account{
			Id:   user.UUID,
			Flow: c.nodeInfo.VlessFlow,
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user),
			Account: serial.ToTypedMessage(vlessAccount),
		}
	}
	return users
}

func (c *Controller) buildTrojanUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))
	for i, user := range *userInfo {
		trojanAccount := &trojan.Account{
			Password: user.UUID,
		}
		users[i] = &protocol.User{
			Level:   0,
			Email:   c.buildUserTag(&user),
			Account: serial.ToTypedMessage(trojanAccount),
		}
	}
	return users
}

func (c *Controller) buildSSUser(userInfo *[]api.UserInfo, method string) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))

	for i, user := range *userInfo {
		normalized, ss2022, err := classifyShadowsocksMethod(method)
		if err != nil {
			log.Error(fmt.Errorf("[UID: %d] %s", user.UID, err))
			continue
		}
		// shadowsocks2022 Key = "openssl rand -base64 32" and multi users needn't cipher method
		if ss2022 {
			e := c.buildUserTag(&user)
			userKey, err := c.checkShadowsocksPassword(user.Passwd, normalized)
			if err != nil {
				log.Error(fmt.Errorf("[UID: %d] %s", user.UID, err))
				continue
			}
			users[i] = &protocol.User{
				Level: 0,
				Email: e,
				Account: serial.ToTypedMessage(&shadowsocks_2022.Account{
					Key: userKey,
				}),
			}
		} else {
			cipher, err := cipherFromString(normalized)
			if err != nil {
				log.Error(fmt.Errorf("[UID: %d] %s", user.UID, err))
				continue
			}
			users[i] = &protocol.User{
				Level: 0,
				Email: c.buildUserTag(&user),
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   user.Passwd,
					CipherType: cipher,
				}),
			}
		}
	}
	return users
}

func (c *Controller) buildSSPluginUser(userInfo *[]api.UserInfo) (users []*protocol.User) {
	users = make([]*protocol.User, len(*userInfo))

	for i, user := range *userInfo {
		normalized, ss2022, err := classifyShadowsocksMethod(user.Method)
		if err != nil {
			log.Error(fmt.Errorf("[UID: %d] %s", user.UID, err))
			continue
		}
		// shadowsocks2022 Key = openssl rand -base64 32 and multi users needn't cipher method
		if ss2022 {
			e := c.buildUserTag(&user)
			userKey, err := c.checkShadowsocksPassword(user.Passwd, normalized)
			if err != nil {
				log.Error(fmt.Errorf("[UID: %d] %s", user.UID, err))
				continue
			}
			users[i] = &protocol.User{
				Level: 0,
				Email: e,
				Account: serial.ToTypedMessage(&shadowsocks_2022.Account{
					Key: userKey,
				}),
			}
		} else {
			cypherMethod, err := cipherFromString(normalized)
			if err != nil {
				log.Error(fmt.Errorf("[UID: %d] %s", user.UID, err))
				continue
			}
			users[i] = &protocol.User{
				Level: 0,
				Email: c.buildUserTag(&user),
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   user.Passwd,
					CipherType: cypherMethod,
				}),
			}
		}
	}
	return users
}

// classifyShadowsocksMethod maps panel cipher names onto xray-core v26.
// none/plain were removed with CipherType_NONE. 2022-blake3-chacha20-poly1305
// has no multi-user inbound, which is the model every panel node uses.
func classifyShadowsocksMethod(method string) (normalized string, ss2022 bool, err error) {
	m := strings.ToLower(strings.TrimSpace(method))
	switch m {
	case "":
		return "", false, fmt.Errorf("shadowsocks cipher method is empty")
	case "none", "plain":
		return "", false, fmt.Errorf("shadowsocks cipher %q is not supported: xray-core removed the none/plain cipher; use an AEAD method (aes-128-gcm, aes-256-gcm, chacha20-poly1305, xchacha20-poly1305) or Shadowsocks 2022 (2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm)", m)
	case "aes-128-gcm", "aead_aes_128_gcm":
		return "aes-128-gcm", false, nil
	case "aes-256-gcm", "aead_aes_256_gcm":
		return "aes-256-gcm", false, nil
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return "chacha20-poly1305", false, nil
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		return "xchacha20-poly1305", false, nil
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		return m, true, nil
	case "2022-blake3-chacha20-poly1305":
		return "", false, fmt.Errorf("shadowsocks cipher %q cannot serve multiple users on xray-core v26 (only 2022-blake3-aes-128-gcm and 2022-blake3-aes-256-gcm have a multi-user inbound)", m)
	default:
		if _, methodErr := shadowsocks_2022.GetCipherMethod(m); methodErr == nil {
			return "", false, fmt.Errorf("shadowsocks cipher %q is not supported for a multi-user node", m)
		}
		return "", false, fmt.Errorf("unknown shadowsocks cipher method: %q", method)
	}
}

func cipherFromString(c string) (shadowsocks.CipherType, error) {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "aes-128-gcm", "aead_aes_128_gcm":
		return shadowsocks.CipherType_AES_128_GCM, nil
	case "aes-256-gcm", "aead_aes_256_gcm":
		return shadowsocks.CipherType_AES_256_GCM, nil
	case "chacha20-poly1305", "aead_chacha20_poly1305", "chacha20-ietf-poly1305":
		return shadowsocks.CipherType_CHACHA20_POLY1305, nil
	case "xchacha20-poly1305", "aead_xchacha20_poly1305", "xchacha20-ietf-poly1305":
		return shadowsocks.CipherType_XCHACHA20_POLY1305, nil
	case "none", "plain":
		return shadowsocks.CipherType_UNKNOWN, fmt.Errorf("shadowsocks cipher %q is not supported: xray-core removed the none/plain cipher", strings.ToLower(strings.TrimSpace(c)))
	default:
		return shadowsocks.CipherType_UNKNOWN, fmt.Errorf("unknown shadowsocks cipher method: %q", c)
	}
}

func (c *Controller) buildUserTag(user *api.UserInfo) string {
	return fmt.Sprintf("%s|%s|%d", c.Tag, user.Email, user.UID)
}

func (c *Controller) checkShadowsocksPassword(password string, method string) (string, error) {
	if strings.Contains(c.panelType, "V2board") {
		var userKey string
		if len(password) < 16 {
			return "", newError("shadowsocks2022 key's length must be greater than 16")
		}
		if method == "2022-blake3-aes-128-gcm" {
			userKey = password[:16]
		} else {
			if len(password) < 32 {
				return "", newError("shadowsocks2022 key's length must be greater than 32")
			}
			userKey = password[:32]
		}
		return base64.StdEncoding.EncodeToString([]byte(userKey)), nil
	} else {
		return password, nil
	}
}

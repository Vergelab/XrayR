package controller

import (
	"fmt"

	"github.com/xtls/xray-core/core"

	"github.com/Vergelab/XrayR/api"
)

// builtNode is an inbound/outbound pair that has been built but not added.
// Building it does not touch the running inbound, so a bad config leaves the
// old listener in place.
type builtNode struct {
	tag      string
	inbound  *core.InboundHandlerConfig
	outbound *core.OutboundHandlerConfig
	extraTag string
	extraIn  *core.InboundHandlerConfig
	extraOut *core.OutboundHandlerConfig
}

func (c *Controller) buildNode(info *api.NodeInfo, tag string) (*builtNode, error) {
	if info.NodeType != "Shadowsocks-Plugin" {
		inbound, err := InboundBuilder(c.config, info, tag)
		if err != nil {
			return nil, err
		}
		outbound, err := OutboundBuilder(c.config, info, tag)
		if err != nil {
			return nil, err
		}
		return &builtNode{tag: tag, inbound: inbound, outbound: outbound}, nil
	}

	ss := *info
	ss.TransportProtocol = "tcp"
	ss.EnableTLS = false
	inbound, err := InboundBuilder(c.config, &ss, tag)
	if err != nil {
		return nil, err
	}
	outbound, err := OutboundBuilder(c.config, &ss, tag)
	if err != nil {
		return nil, err
	}
	door := *info
	door.Port++
	door.NodeType = "dokodemo-door"
	extra := fmt.Sprintf("dokodemo-door_%s+1", tag)
	extraIn, err := InboundBuilder(c.config, &door, extra)
	if err != nil {
		return nil, err
	}
	extraOut, err := OutboundBuilder(c.config, &door, extra)
	if err != nil {
		return nil, err
	}
	return &builtNode{
		tag: tag, inbound: inbound, outbound: outbound,
		extraTag: extra, extraIn: extraIn, extraOut: extraOut,
	}, nil
}

func (c *Controller) installNode(n *builtNode) error {
	if err := c.addInbound(n.inbound); err != nil {
		return err
	}
	if err := c.addOutbound(n.outbound); err != nil {
		_ = c.removeInbound(n.tag)
		return err
	}
	if n.extraIn == nil {
		return nil
	}
	if err := c.addInbound(n.extraIn); err != nil {
		_ = c.removeOutbound(n.tag)
		_ = c.removeInbound(n.tag)
		return err
	}
	if err := c.addOutbound(n.extraOut); err != nil {
		_ = c.removeInbound(n.extraTag)
		_ = c.removeOutbound(n.tag)
		_ = c.removeInbound(n.tag)
		return err
	}
	return nil
}

func (c *Controller) uninstallNode(info *api.NodeInfo, tag string) error {
	if err := c.removeOldTag(tag); err != nil {
		return err
	}
	if info != nil && info.NodeType == "Shadowsocks-Plugin" {
		extra := fmt.Sprintf("dokodemo-door_%s+1", tag)
		if err := c.removeOldTag(extra); err != nil {
			return err
		}
	}
	return nil
}

// replaceNode builds the new inbound before removing the old one. A build
// error leaves the old inbound serving and does not record the new node.
// The port (and the tag, which includes the port) cannot be bound twice, so
// the swap is remove-then-add. If add fails, the previously built old inbound
// is installed again.
func (c *Controller) replaceNode(oldInfo *api.NodeInfo, oldTag string, newInfo *api.NodeInfo) error {
	newTag := fmt.Sprintf("%s_%s_%d", newInfo.NodeType, c.config.ListenIP, newInfo.Port)
	prepared, err := c.buildNode(newInfo, newTag)
	if err != nil {
		return err
	}
	rollback, err := c.buildNode(oldInfo, oldTag)
	if err != nil {
		return fmt.Errorf("prepare rollback inbound: %w", err)
	}

	c.mu.RLock()
	users := c.userList
	c.mu.RUnlock()

	if err := c.uninstallNode(oldInfo, oldTag); err != nil {
		c.logger.Printf("remove old inbound %s failed: %v", oldTag, err)
		c.restoreNode(rollback, oldTag, oldInfo, users)
		return err
	}
	if err := c.installNode(prepared); err != nil {
		c.logger.Printf("install new inbound %s failed: %v; rolling back to %s", newTag, err, oldTag)
		c.restoreNode(rollback, oldTag, oldInfo, users)
		return err
	}

	c.mu.Lock()
	c.nodeInfo = newInfo
	c.Tag = newTag
	c.mu.Unlock()
	return nil
}

func (c *Controller) restoreNode(n *builtNode, tag string, info *api.NodeInfo, users *[]api.UserInfo) {
	if err := c.installNode(n); err != nil {
		c.logger.Printf("rollback inbound %s failed: %v", tag, err)
		return
	}
	c.mu.Lock()
	c.Tag = tag
	c.nodeInfo = info
	c.mu.Unlock()
	if users != nil {
		if err := c.addNewUser(users, info); err != nil {
			c.logger.Printf("rollback users on %s failed: %v", tag, err)
		}
	}
}

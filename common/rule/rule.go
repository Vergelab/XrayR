// Package rule is to control the audit rule behaviors
package rule

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/Vergelab/XrayR/api"
	mapset "github.com/deckarep/golang-set"
	log "github.com/sirupsen/logrus"
)

type Manager struct {
	InboundRule         *sync.Map // Key: Tag, Value: []api.DetectRule
	InboundDetectResult *sync.Map // key: Tag, Value: *hitSet
}

// hitSet guards one tag's detect results. mapset.NewSet is thread-safe, and
// the mutex keeps iteration in GetDetectResult from racing a concurrent Add.
type hitSet struct {
	mu  sync.Mutex
	set mapset.Set
}

func New() *Manager {
	return &Manager{
		InboundRule:         new(sync.Map),
		InboundDetectResult: new(sync.Map),
	}
}

func (r *Manager) UpdateRule(tag string, newRuleList []api.DetectRule) error {
	copied := append([]api.DetectRule(nil), newRuleList...)
	if value, ok := r.InboundRule.LoadOrStore(tag, copied); ok {
		oldRuleList := value.([]api.DetectRule)
		if !reflect.DeepEqual(oldRuleList, copied) {
			r.InboundRule.Store(tag, copied)
		}
	}
	return nil
}

func (r *Manager) GetDetectResult(tag string) (*[]api.DetectResult, error) {
	detectResult := make([]api.DetectResult, 0)
	if value, ok := r.InboundDetectResult.LoadAndDelete(tag); ok {
		hits := value.(*hitSet)
		hits.mu.Lock()
		it := hits.set.Iterator()
		for result := range it.C {
			detectResult = append(detectResult, result.(api.DetectResult))
		}
		hits.mu.Unlock()
	}
	return &detectResult, nil
}

func (r *Manager) Detect(tag string, destination string, email string) (reject bool) {
	reject = false
	var hitRuleID = -1
	// If we have some rule for this inbound
	if value, ok := r.InboundRule.Load(tag); ok {
		ruleList := value.([]api.DetectRule)
		for _, r := range ruleList {
			if r.Pattern.Match([]byte(destination)) {
				hitRuleID = r.ID
				reject = true
				break
			}
		}
		// If we hit some rule
		if reject && hitRuleID != -1 {
			l := strings.Split(email, "|")
			uid, err := strconv.Atoi(l[len(l)-1])
			if err != nil {
				log.Debug(fmt.Sprintf("Record illegal behavior failed! Cannot find user's uid: %s", email))
				return reject
			}
			fresh := &hitSet{set: mapset.NewSetWith(api.DetectResult{UID: uid, RuleID: hitRuleID})}
			if v, ok := r.InboundDetectResult.LoadOrStore(tag, fresh); ok {
				hits := v.(*hitSet)
				hits.mu.Lock()
				hits.set.Add(api.DetectResult{UID: uid, RuleID: hitRuleID})
				hits.mu.Unlock()
			}
		}
	}
	return reject
}

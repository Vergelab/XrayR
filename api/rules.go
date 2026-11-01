package api

import (
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

// CompileRule compiles one audit rule. An empty pattern or a pattern that
// does not compile is skipped and logged. Patterns are unanchored: "."
// matches any character, and a successful match blocks the destination.
func CompileRule(id int, pattern string) (DetectRule, bool) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		log.Warnf("skip empty detect rule %d", id)
		return DetectRule{}, false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		log.Warnf("skip detect rule %d %q: %v", id, pattern, err)
		return DetectRule{}, false
	}
	return DetectRule{ID: id, Pattern: re}, true
}

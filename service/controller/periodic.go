package controller

import (
	"runtime/debug"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// periodicTask runs one monitor loop. A panic in execute is logged and the
// loop continues, so one bad poll does not kill the process. The interval
// function is read after every run, which is how a panel push_interval
// replaces UpdatePeriodic without restarting the task.
type periodicTask struct {
	tag      string
	interval func() time.Duration
	execute  func() error
	stop     chan struct{}
	once     sync.Once
}

func (p *periodicTask) Start() {
	if p.stop == nil {
		p.stop = make(chan struct{})
	}
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("%s periodic task recovered from panic: %v\n%s", p.tag, r, debug.Stack())
				}
			}()
			if p.execute == nil {
				return
			}
			if err := p.execute(); err != nil {
				log.Printf("%s periodic task: %v", p.tag, err)
			}
		}()
		wait := time.Second
		if p.interval != nil {
			if next := p.interval(); next > 0 {
				wait = next
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-p.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (p *periodicTask) Close() error {
	p.once.Do(func() {
		if p.stop == nil {
			p.stop = make(chan struct{})
		}
		close(p.stop)
	})
	return nil
}

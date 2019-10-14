// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build cgo
// +build amd64
// +build !windows
// +build !sqreen_nowaf

package waf_test

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/sqreen/go-libsqreen/waf"
	"github.com/sqreen/go-libsqreen/waf/types"
	"github.com/stretchr/testify/require"
)

func TestUsage(t *testing.T) {
	t.Run("hello, waf!", func(t *testing.T) {
		t.Run("version", func(t *testing.T) {
			v := waf.Version()
			require.NotNil(t, v)
			require.Equal(t, "0.4.0", *v)
		})

		t.Run("monitor", func(t *testing.T) {
			r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}")
			require.NoError(t, err)
			defer r.Close()
			action, match, err := r.Run(types.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
			require.NoError(t, err)
			require.Equal(t, types.MonitorAction, action)
			require.NotEmpty(t, match)
		})

		t.Run("block", func(t *testing.T) {
			r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_block\"}]}]}")
			require.NoError(t, err)
			defer r.Close()
			action, match, err := r.Run(types.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
			require.NoError(t, err)
			require.Equal(t, types.BlockAction, action)
			require.NotEmpty(t, match)
		})

		t.Run("no action", func(t *testing.T) {
			r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_block\"}]}]}")
			require.NoError(t, err)
			defer r.Close()
			action, match, err := r.Run(types.RunInput{"#._server['HTTP_USER_AGENT']": "go client"}, time.Second)
			require.NoError(t, err)
			require.Equal(t, types.NoAction, action)
			require.Empty(t, match)
		})

		t.Run("timeout", func(t *testing.T) {
			r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_block\"}]}]}")
			require.NoError(t, err)
			defer r.Close()
			action, match, err := r.Run(types.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, 0)
			require.Equal(t, types.ErrTimeout, err)
			require.Equal(t, types.NoAction, action)
			require.Empty(t, match)
		})
	})

	t.Run("update an existing rule", func(t *testing.T) {
		r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}")
		require.NoError(t, err)
		action, match, err := r.Run(types.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, types.MonitorAction, action)
		require.NotEmpty(t, match)

		r, err = waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Toto\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}")
		require.NoError(t, err)
		// It should no longer be detected
		action, match, err = r.Run(types.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, types.NoAction, action)
		require.Empty(t, match)
		r.Close()
	})

	t.Run("one rule - 8000 concurrent users", func(t *testing.T) {
		// Create a store that will be checked more often than actually required by
		// its period. So that we cover the case where the store is not always
		// ready.
		r, err := waf.NewRule("rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]},{\"rule_id\": \"2\",\"filters\": [{\"operator\": \"@pm\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": [\"bla\", \"blo\", \"Toto\"]}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\",\"2\"],\"on_match\": \"exit_monitor\"}]}]}")
		require.NoError(t, err)
		defer r.Close()

		userAgents := [...]string{"Arachni", "Toto", "Tata", "Titi"}
		okIndex := 1

		// Start 8000 users that will use the rule 1000 times each
		nbUsers := 8000
		nbRun := 100

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch and
		// increase the chances of parallel accesses
		startBarrier.Add(nbUsers)
		// Create a stopBarrier to signal when all user goroutines are done.
		stopBarrier.Add(nbUsers)

		for n := 0; n < nbUsers; n++ {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning
				for c := 0; c < nbRun; c++ {
					i := rand.Int() % len(userAgents)
					action, match, err := r.Run(types.RunInput{"#._server['HTTP_USER_AGENT']": userAgents[i]}, time.Second)
					require.NoError(t, err)
					if i <= okIndex {
						require.Equal(t, types.MonitorAction, action)
						require.NotEmpty(t, match)
					} else {
						require.Equal(t, types.NoAction, action)
						require.Empty(t, match)
					}
				}
			}()
		}

		// Save the test start time to compare it to the first metrics store's
		// that should be latter.
		startBarrier.Add(-nbUsers) // Unblock the user goroutines
		stopBarrier.Wait()         // Wait for the user goroutines to be done
	})

	t.Run("one concurrent updater - 8000 concurrent users", func(t *testing.T) {
		userAgents := [...]string{"Arachni", "Toto", "Tata", "Titi"}
		var (
			currentUserAgentIndex int
			ruleID                int
			rule                  types.Rule
			lock                  sync.RWMutex
		)
		updateRule := func() (previousRule types.Rule) {
			lock.Lock()
			defer lock.Unlock()

			// Select a random user agent
			currentUserAgentIndex = rand.Intn(len(userAgents))
			userAgent := userAgents[currentUserAgentIndex]
			// Create a new rule id that was never used before
			ruleIDStr := fmt.Sprintf("rule-%d", ruleID)
			ruleID++
			// Create a WAF rule with the selected user agent
			wafRule := fmt.Sprintf(`{"rules": [{"rule_id": "1","filters": [{"operator": "@rx","targets": ["#._server['HTTP_USER_AGENT']"],"value": "%s"}]}],"flows": [{"name": "arachni_detection","steps": [{"id": "start","rule_ids": ["1"],"on_match": "exit_monitor"}]}]}`, userAgent)

			// Save the current rule to return it in order to free it out of this
			// locked section.
			lastRule := rule

			// Create the new rule
			var err error
			rule, err = waf.NewRule(ruleIDStr, wafRule)
			require.NoError(t, err)
			return lastRule
		}

		// Create a first rule it before starting the goroutines that will use it.
		updateRule()

		// The WAF rule will be updated once per second
		updatePeriod := 100 * time.Millisecond
		tick := time.Tick(updatePeriod)

		// Signal channel between this test and the updater to tear down the test
		done := make(chan struct{})

		// One updater
		go func() {
			for {
				select {
				case <-tick:
					prev := updateRule()
					// Release the previous rule concurrently.
					prev.Close()

				case <-done:
					// All goroutines are done: notify we are done too.
					close(done)
					return
				}
			}
		}()

		// Start 8000 rule users that will use the rule 1000 times each
		nbUsers := 8000
		nbRun := 100

		var startBarrier, stopBarrier sync.WaitGroup
		// Create a start barrier to synchronize every goroutine's launch
		startBarrier.Add(nbUsers)
		// Create a stopBarrier to signal when all goroutines are done writing
		// their values
		stopBarrier.Add(nbUsers)

		for n := 0; n < nbUsers; n++ {
			go func() {
				startBarrier.Wait()      // Sync the starts of the goroutines
				defer stopBarrier.Done() // Signal we are done when returning
				for c := 0; c < nbRun; c++ {
					lock.RLock()
					// Select a random user agent
					myUserAgentIndex := rand.Intn(len(userAgents))
					myUserAgent := userAgents[myUserAgentIndex]
					// Use the rule
					action, match, err := rule.Run(types.RunInput{"#._server['HTTP_USER_AGENT']": myUserAgent}, time.Second)
					require.NoError(t, err)
					if myUserAgentIndex == currentUserAgentIndex {
						require.Equal(t, types.MonitorAction, action)
						require.NotEmpty(t, match)
					} else {
						require.Equal(t, types.NoAction, action)
						require.Empty(t, match)
					}
					lock.RUnlock()
				}
			}()
		}

		// Save the test start time to compare it to the first metrics store's
		// that should be latter.
		startBarrier.Add(-nbUsers) // Unblock the writer goroutines
		stopBarrier.Wait()         // Wait for the writer goroutines to be done
		done <- struct{}{}         // Signal the reader they are done
		<-done                     // Wait for the reader to be done
	})
}

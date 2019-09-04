// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package waf_test

import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/sqreen/AgentGoNative/waf"
	"github.com/stretchr/testify/require"
)

func TestUsage(t *testing.T) {
	//waf.SetupLogging()

	t.Run("hello, waf!", func(t *testing.T) {
		t.Run("monitor", func(t *testing.T) {
			r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}")
			defer r.Close()
			require.NoError(t, err)
			action, match, err := r.Run(waf.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
			require.NoError(t, err)
			require.Equal(t, waf.MonitorAction, action)
			require.NotEmpty(t, match)
		})

		t.Run("block", func(t *testing.T) {
			r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_block\"}]}]}")
			defer r.Close()
			require.NoError(t, err)
			action, match, err := r.Run(waf.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
			require.NoError(t, err)
			require.Equal(t, waf.BlockAction, action)
			require.NotEmpty(t, match)
		})

		t.Run("no action", func(t *testing.T) {
			r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_block\"}]}]}")
			defer r.Close()
			require.NoError(t, err)
			action, match, err := r.Run(waf.RunInput{"#._server['HTTP_USER_AGENT']": "go client"}, time.Second)
			require.NoError(t, err)
			require.Equal(t, waf.NoAction, action)
			require.Empty(t, match)
		})
	})

	t.Run("update an existing rule", func(t *testing.T) {
		r, err := waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}")
		require.NoError(t, err)
		action, match, err := r.Run(waf.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, waf.MonitorAction, action)
		require.NotEmpty(t, match)

		r, err = waf.NewRule("my rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Toto\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}")
		require.NoError(t, err)
		// It should no longer be detected
		action, match, err = r.Run(waf.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, waf.NoAction, action)
		require.Empty(t, match)
		r.Close()
	})

	t.Run("one rule - 8000 parallel users", func(t *testing.T) {
		// Create a store that will be checked more often than actually required by
		// its period. So that we cover the case where the store is not always
		// ready.
		r, err := waf.NewRule("rule", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}")
		require.NoError(t, err)

		userAgents := [...]string{"Arachni", "Toto", "Tata", "Titi"}
		okIndex := 0

		// Start 8000 users that will use the rule 1000 times each
		nbUsers := 8000
		nbRun := 1000

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
					rule := (*waf.Rule)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&r))))
					action, match, err := rule.Run(waf.RunInput{"#._server['HTTP_USER_AGENT']": userAgents[i]}, time.Second)
					require.NoError(t, err)
					if i == okIndex {
						require.Equal(t, waf.MonitorAction, action)
						require.NotEmpty(t, match)
					} else {
						require.Equal(t, waf.NoAction, action)
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

	t.Run("one concurrent updater - 8000 parallel users", func(t *testing.T) {
		// Create a store that will be checked more often than actually required by
		// its period. So that we cover the case where the store is not always
		// ready.
		r, err := waf.NewRule("rule-0", "{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}")
		require.NoError(t, err)

		// The reader will be awaken 4 times per store period, so only it will see
		// a ready store only once out of four.
		updatePeriod := time.Second
		tick := time.Tick(updatePeriod)

		// Signal channel between this test and the reader to tear down the test
		done := make(chan struct{})

		userAgents := [...]string{"Arachni", "Toto", "Tata", "Titi"}

		// One updater
		go func() {
			rid := 0
			for {
				select {
				case <-tick:
					userAgent := userAgents[rid%2] // 0 or 1
					wafRule := fmt.Sprintf(`{"rules": [{"rule_id": "1","filters": [{"operator": "@rx","targets": ["#._server['HTTP_USER_AGENT']"],"value": "%s"}]}],"flows": [{"name": "arachni_detection","steps": [{"id": "start","rule_ids": ["1"],"on_match": "exit_monitor"}]}]}`, userAgent)
					newRule, err := waf.NewRule(fmt.Sprintf("rule-%d", rid), wafRule)
					rid++
					require.NoError(t, err)
					currentRule := r
					atomic.SwapPointer((*unsafe.Pointer)(unsafe.Pointer(&r)), unsafe.Pointer(newRule))
					currentRule.Close()

				case <-done:
					// All goroutines are done: notify we are done too.
					close(done)
					return
				}
			}
		}()

		// Start 8000 rule users that will use the rule 1000 times each
		nbUsers := 8000
		nbRun := 1000

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
					i := rand.Int() % len(userAgents)
					rule := (*waf.Rule)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&r))))
					_, _, err := rule.Run(waf.RunInput{"#._server['HTTP_USER_AGENT']": userAgents[i]}, time.Second)
					require.NoError(t, err)
					//require.Equal(t, waf.NoAction, action)
					//require.Empty(t, match)
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

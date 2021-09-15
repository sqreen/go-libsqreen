// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

// +build cgo
// +build amd64
// +build !windows

package waf_test

import (
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/sqreen/go-libsqreen/waf"
	"github.com/sqreen/go-libsqreen/waf/types"
	"github.com/stretchr/testify/require"
)

func TestUsage(t *testing.T) {
	t.Parallel()
	t.Run("version", func(t *testing.T) {
		t.Parallel()
		v := waf.Version()
		require.NotNil(t, v)
		require.Equal(t, "1.0.6", *v)
		require.NoError(t, waf.Health())
	})

	t.Run("monitor", func(t *testing.T) {
		t.Parallel()
		rule := newTestRule("exit_monitor")
		r, err := waf.NewRule(rule)
		require.NoError(t, err)
		defer r.Close()

		// Match input
		action, match, err := r.Run(types.DataSet{"user-agent": "Arachni"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, types.MonitorAction, action)
		require.NotEmpty(t, match)

		// Non matching input
		action, match, err = r.Run(types.DataSet{"user-agent": "go client"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, types.NoAction, action)
		require.Empty(t, match)

		// Missing input
		action, match, err = r.Run(types.DataSet{"something": "Arachni"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, types.NoAction, action)
		require.Empty(t, match)
	})

	t.Run("block", func(t *testing.T) {
		t.Parallel()
		rule := newTestRule("exit_block")
		r, err := waf.NewRule(rule)
		require.NoError(t, err)
		defer r.Close()

		// Matching input
		action, match, err := r.Run(types.DataSet{"user-agent": "Arachni"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, types.BlockAction, action)
		require.NotEmpty(t, match)

		// Non matching input
		action, match, err = r.Run(types.DataSet{"user-agent": "go client"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, types.NoAction, action)
		require.Empty(t, match)

		// Missing input
		action, match, err = r.Run(types.DataSet{"something": "Arachni"}, time.Second)
		require.NoError(t, err)
		require.Equal(t, types.NoAction, action)
		require.Empty(t, match)
	})

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		rule := newTestRule("exit_block")
		r, err := waf.NewRule(rule)
		require.NoError(t, err)
		defer r.Close()

		action, match, err := r.Run(types.DataSet{"user-agent": "go client"}, 0)
		require.Equal(t, types.ErrTimeout, err)
		require.Equal(t, types.NoAction, action)
		require.Empty(t, match)
	})

	t.Run("one rule - 8000 concurrent users", func(t *testing.T) {
		t.Parallel()
		rule := newTestRule("exit_block")
		r, err := waf.NewRule(rule)
		require.NoError(t, err)
		defer r.Close()

		userAgents := [...]string{"Arachni", "Toto", "Tata", "Titi"}
		blockingUserAgentIndex := 0

		// Start 5000 users that will use the rule 1000 times each
		nbUsers := 5000
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
					i := c % len(userAgents)
					action, match, err := r.Run(types.DataSet{"user-agent": userAgents[i]}, time.Minute)
					if err != nil {
						t.Fatal(err)
					}
					if i == blockingUserAgentIndex && (action != types.BlockAction || len(match) == 0) {
						t.Fatalf("action=`%v` match=`%v`", action, string(match))
					} else if i != blockingUserAgentIndex && (action != types.NoAction || len(match) > 0) {
						t.Fatalf("action=`%v` match=`%v`", action, string(match))
					}
				}
			}()
		}

		// Save the test start time to compare it to the first metrics store's
		// that should be latter.
		startBarrier.Add(-nbUsers) // Unblock the user goroutines
		stopBarrier.Wait()         // Wait for the user goroutines to be done
	})
}

var tmpl = template.Must(template.New("").Parse(`
{
  "manifest": {
    "user-agent": {
      "inherit_from": "user-agent",
      "run_on_value": true,
      "run_on_key": false
    }
  },
  "rules": [
    {
      "rule_id": "1",
      "filters": [
        {
          "operator": "@rx",
          "targets": [
            "user-agent"
          ],
          "value": "Arachni"
        }
      ]
    }
  ],
  "flows": [
    {
      "name": "arachni_detection",
      "steps": [
        {
          "id": "start",
          "rule_ids": [
            "1"
          ],
          "on_match": "{{ .OnMatchAction }}"
        }
      ]
    }
  ]
}
`))

func newTestRule(onMatchAction string) string {
	var str strings.Builder
	tmpl.Execute(&str, struct {
		OnMatchAction string
	}{
		OnMatchAction: onMatchAction,
	})
	return str.String()
}

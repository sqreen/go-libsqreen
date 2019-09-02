// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package waf_test

import (
	"testing"
	"time"

	"github.com/sqreen/AgentGoNative/waf"
	"github.com/stretchr/testify/require"
)

func TestUsage(t *testing.T) {
	r, err := waf.NewRule("my rule", []byte("{\"rules\": [{\"rule_id\": \"1\",\"filters\": [{\"operator\": \"@rx\",\"targets\": [\"#._server['HTTP_USER_AGENT']\"],\"value\": \"Arachni\"}]}],\"flows\": [{\"name\": \"arachni_detection\",\"steps\": [{\"id\": \"start\",\"rule_ids\": [\"1\"],\"on_match\": \"exit_monitor\"}]}]}"))
	defer r.Close()
	require.NoError(t, err)
	action, match, err := r.Run(waf.RunInput{"#._server['HTTP_USER_AGENT']": "Arachni"}, time.Second)
	require.NoError(t, err)
	require.Equal(t, waf.MonitorAction, action)
	require.NotEmpty(t, match)
}

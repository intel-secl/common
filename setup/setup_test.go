/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSomething(t *testing.T) {

	var a string = "Hello"
	var b string = "Hello"

	assert.Equal(t, a, b, "The two words should be the same.")

}

func TestOverrideValueFromEnvVarStringVals(t *testing.T) {
	ctx := Context{
		askInput: false,
	}

	user := "Hello"
	os.Unsetenv("TRUSTAGENT_USER")

	ctx.OverrideValueFromEnvVar("TRUSTAGENT_USER", &user, "trust agent username", false)
	assert.Equal(t, user, "Hello", "there is no env value - so we shoud get the currently set value")

	os.Setenv("TRUSTAGENT_USER", "tagent")
	ctx.OverrideValueFromEnvVar("TRUSTAGENT_USER", &user, "trust agent username", false)
	assert.Equal(t, "tagent", user, "reading from env variable - should get value from env variable")

	os.Unsetenv("TRUSTAGENT_USER")
	ctx.OverrideValueFromEnvVar("TRUSTAGENT_USER", &user, "trust agent username", false)
	assert.Equal(t, "tagent", user, "there is no env value - so we shoud get the currently set value")

	user = "newuser"
	ctx.OverrideValueFromEnvVar("TRUSTAGENT_USER", &user, "trust agent username", false)
	assert.Equal(t, "newuser", user, "there is no env value - so we shoud get the newly set value")

	os.Setenv("TRUSTAGENT_USER", "")
	ctx.OverrideValueFromEnvVar("TRUSTAGENT_USER", &user, "trust agent username", true)
	assert.Equal(t, "", user, "there is no env value - so we shoud get the newly set value")

	_, _, err := ctx.OverrideValueFromEnvVar("TRUSTAGENT_USER", &user, "trust agent username", false)
	assert.EqualError(t, err, "env var TRUSTAGENT_USER cannot be empty")

	os.Unsetenv("TRUSTAGENT_USER")

	fmt.Println("done")
}

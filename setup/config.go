/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"errors"
	"os"

	"intel/isecl/lib/common/v5/serialize"
)

type Config struct {
	FilePath  string
	ConfigObj interface{}
	Vars      []EnvVars
}

var ErrConfigFailed = errors.New("Failed to retrieve all required configuration variables fron env.")

// Run reads in configuration items from env and save configuration object
// to the given file path as a yaml file
func (conf Config) Run(c Context) error {

	failed := false
	for _, v := range conf.Vars {
		_, _, err := c.OverrideValueFromEnvVar(v.Name, v.ConfigVar, v.Description, v.EmptyOkay)
		failed = failed || ((!v.EmptyOkay) && (err != nil))
	}
	if failed {
		return ErrConfigFailed
	}
	return serialize.SaveToYamlFile(conf.FilePath, conf.ConfigObj)
}

// Validate check if the configuration file already exists
func (cnfr Config) Validate(c Context) error {

	if _, err := os.Stat(cnfr.FilePath); err != nil {
		if os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

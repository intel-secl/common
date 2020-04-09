/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"fmt"
	"github.com/pkg/errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	commLog "intel/isecl/lib/common/v2/log"
)

var log = commLog.GetDefaultLogger()
// Task defines a Setup Task. Run() executes the setup task, and Validate() checks whether or not the task succeeded.
// Validate() can and should be run as the first statement of Run() so needless work isn't done again.
type Task interface {
	Run(c Context) error
	Validate(c Context) error
}

// Runner is a task runner for generic Task interfaces. It stores a list of Tasks that will be executed in the
// order they are found in the list. The runner can also be configured to opt-in to ask for user input from stdin
type Runner struct {
	Tasks    []Task
	AskInput bool
}

// Context contains contextual setup runner information
// if askInput is false (default value), the setup task should NOT block and wait for user input
type Context struct {
	askInput bool
}

// EnvVars data structure is used to hold attributes of an environment variable and the underlying configruation
// value. You can have an array of this struct to either pass to a function or use it in a loop.
type EnvVars struct {
	Name        string
	ConfigVar   interface{}
	Description string
	EmptyOkay   bool
}

// RunTasks executes the specified set of Tasks against the registered list of tasks. Any tasks registered that arent in the list provided are skipped.
func (r *Runner) RunTasks(tasks ...string) error {
	ctx := Context{
		askInput: r.AskInput,
	}
	if len(tasks) == 0 {
		// run ALL the setup tasks
		fmt.Println("Running setup ...")
		for _, t := range r.Tasks {
			taskName := strings.ToLower(reflect.TypeOf(t).Name())
			if err := t.Run(ctx); err != nil {
				fmt.Fprintln(os.Stderr,"Error while running setup task:",taskName)
				return errors.Wrapf(err, "setup/setup.go:RunTasks() Error while running setup task %s", taskName)
			}
			if err := t.Validate(ctx); err != nil {
				fmt.Fprintln(os.Stderr,"Error while validating setup task:",taskName)
				return errors.Wrapf(err, "setup/setup.go:RunTasks() Error while validating setup task %s", taskName)
			}
		}
		fmt.Println("Setup finished successfully!")
	} else {
		// map each task ...string into a map[string]bool
		enabledTasks := make(map[string]bool)
		for _, t := range tasks {
			enabledTasks[strings.ToLower(t)] = true
		}
		// iterate through the proper order of tasks, and execute the ones listed in the parameters
		for _, t := range r.Tasks {
			taskName := strings.ToLower(reflect.TypeOf(t).Name())
			if _, ok := enabledTasks[taskName]; ok {
				if err := t.Run(ctx); err != nil {
					fmt.Fprintln(os.Stderr,"Error while running setup task:",taskName)
					return errors.Wrapf(err, "setup/setup.go:RunTasks() Error while running setup task %s", taskName)
				}
				if err := t.Validate(ctx); err != nil {
					fmt.Fprintln(os.Stderr,"Error while validating setup task:",taskName)
					return errors.Wrapf(err, "setup/setup.go:RunTasks() Error while validating setup task %s", taskName)
				}
				fmt.Fprintln(os.Stdout,"Setup task finished successfully:",taskName)
			}
		}
	}
	return nil
}

// GetenvInt retrieves an integer variable from the environment
// this function will optionally read input from stdin if it was not defined in the environment,
// if Context.askInput is set to true
func (c Context) GetenvInt(env string, description string) (int, error) {
	fmt.Printf("%s:\n", description)
	if intStr, ok := os.LookupEnv(env); ok {
		val, err := strconv.ParseInt(intStr, 10, 32)
		if err == nil {
			fmt.Println(intStr)
			return int(val), nil
		}
		return 0, fmt.Errorf("%s is not not an integer", env)
	}
	if c.askInput {
		var intValue int
		if scanned, err := fmt.Scanf("%d", &intValue); scanned != 1 || err != nil {
			return 0, fmt.Errorf("error reading value for %s", env)
		}
		return intValue, nil
	}
	return 0, fmt.Errorf("%s is not defined", env)
}

// GetenvString retrieves a string variable from the environment
// this function will optionally read input from stdin if it was not defined in the environment,
// if Context.askInput is set to true
func (c Context) GetenvString(env string, description string) (string, error) {
	fmt.Printf("%s:\n", description)
	if str, ok := os.LookupEnv(env); ok {
		fmt.Println(str)
		return str, nil
	}
	if c.askInput {
		var str string
		if scanned, err := fmt.Scanln(&str); scanned != 1 || err != nil {
			return "", fmt.Errorf("error reading value for %s", env)
		}
		return str, nil
	}
	return "", fmt.Errorf("%s is not defined", env)
}

// GetenvSecret retrieves a string variable from the envrionment that is secret
// this is functionally equivalent to GetenvString, but does not print the read value to stdout
// this function will optionally read input from stdin if it was not defined in the environment,
// if Context.askInput is set to true
func (c Context) GetenvSecret(env string, description string) (string, error) {
	fmt.Printf("%s:\n", description)
	if str, ok := os.LookupEnv(env); ok {
		fmt.Println("****")
		return str, nil
	}
	if c.askInput {
		var str string
		if scanned, err := fmt.Scanln(&str); scanned != 1 || err != nil {
			return "", fmt.Errorf("error reading value for %s", env)
		}
		return str, nil
	}
	return "", fmt.Errorf("%s is not defined", env)
}

// OverrideValueFromEnvVar takes an environment variable name(key). If this variable is exported
// ie - available as an environment variable, we will overwrite the value.
// The zeroValue when set to true means that it is okay to have an empty/ default value.
func (c Context) OverrideValueFromEnvVar(envVar string, i interface{}, desc string, zeroValueOkay bool) (envValueStr string, envVarExists bool, err error) {

	log.Debugf("Reading from Env var and setting Value : %s", desc)
	//validate that value that is passed in is a pointer/ reference since we need to set it
	if reflect.ValueOf(i).Kind() != reflect.Ptr {
		err = fmt.Errorf("expect a pointer for second input parameter 'i' - need to pass address of value")
		return
	}

	err = nil

	// get value from environment variable
	envValueStr, envVarExists = os.LookupEnv(envVar)

	// boolean has to be treated seperately as it has different rules. If the environment variable is
	// set but it does not have a value, it implies true. We will use the zeroValueOkay to determine
	// whether to interpret it in this manner.
	// If type is bool and zeroValueOkay is set, we will set it to true
	if value, ok := i.(*bool); ok {
		if envVarExists {
			if envValueStr == "" {
				if zeroValueOkay {
					*value = true
				} else {
					err = fmt.Errorf("env var %s cannot be empty", envVar)
					*value = false
				}
			} else {
				var boolResult bool
				boolResult, err = strconv.ParseBool(envValueStr)
				if err == nil {
					*value = boolResult
				} else {
					err = fmt.Errorf("env var %s=%s - could not parse boolean value", envVar, envValueStr)
				}

			}
		}
		return
	}

	// condition where the environment variable is at least defined
	if envVarExists {
		switch value := i.(type) {
		case *int:
			var intResult int
			if intResult, err = strconv.Atoi(envValueStr); err == nil {
				*value = intResult
			} else {
				err = fmt.Errorf("env var %s=%s cannot convert to int", envVar, envValueStr)
			}
		case *float64:
			var floatResult float64
			if floatResult, err = strconv.ParseFloat(envValueStr, 64); err == nil {
				*value = floatResult
			} else {
				err = fmt.Errorf("env var %s=%s cannot convert to float64", envVar, envValueStr)
			}
		// Use env variable value if we have ""(empty string ) and it is acceptable
		case *string:
			if zeroValueOkay || envValueStr != "" {
				*value = envValueStr
			} else {
				err = fmt.Errorf("env var %s cannot be empty", envVar)
			}
		default:
			message := "unsupported type for reading from environment variable - " +
				"only int, float64, string and bool currently supported"
			err = fmt.Errorf(message)
		}
		return
	}

	// TODO. Handle the AskInput cases. We are not using it now.
	//if c.AskInput {

	//}

	// If the environment variable was not set, we will use the value that was passed in
	// If zeroValueOkay is not true, then we need to make sure that the underlying values don't have
	// just the default value. 0 for int, float64 false for bool and "" for string
	if !zeroValueOkay {
		switch value := i.(type) {
		case *int:
			if *value == 0 {
				err = fmt.Errorf("env var %s does not exist(or empty) and current value is 0", envVar)
			}
		case *float64:
			if *value == 0 {
				err = fmt.Errorf("env var %s does not exist(or empty) and current value is 0", envVar)
			}
		case *string:
			if *value == "" {
				err = fmt.Errorf("env var %s does not exist(or empty) and current value is empty", envVar)
			}
		default:
			message := "unsupported type in function. " +
				"only int, float64, string and bool supported"
			err = fmt.Errorf(message)
		}
		return
	}

	return
}

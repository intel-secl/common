/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package log

import (
	"runtime"
	"strings"

	"intel/isecl/lib/common/v3/log/setup"

	log "github.com/sirupsen/logrus"
)

var ErrLoggerExists = setup.ErrLoggerExists

const (
	unknownLoggerName  = "unknown"
	DefaultLoggerName  = "default"
	SecurityLoggerName = "security"
)

var defaultLogger *log.Entry
var securityLogger *log.Entry

func init() {
	setup.AddLogger(DefaultLoggerName, "name", log.StandardLogger())
	setup.AddLogger(SecurityLoggerName, "name", log.New())

	setup.AddLogger(unknownLoggerName, "package", log.StandardLogger())
}

func AddLogger(name string, l *log.Logger) error {
	return setup.AddLogger(name, "name", l)
}

func AddLoggerByPackageName() (*log.Entry, string) {
	pc := make([]uintptr, 2)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	pkgName := strings.Split(f.Name(), ".")[0]
	setup.AddLogger(pkgName, "package", log.StandardLogger())
	return setup.GetLogger(pkgName), pkgName
}

func GetLogger(name string) *log.Entry {
	if name == "" {
		return setup.GetLogger(unknownLoggerName)
	}
	return setup.GetLogger(name)
}

func GetDefaultLogger() *log.Entry {
	if defaultLogger == nil {
		defaultLogger = setup.GetLogger(DefaultLoggerName)
	}
	return defaultLogger
}

func GetSecurityLogger() *log.Entry {
	if securityLogger == nil {
		securityLogger = setup.GetLogger(SecurityLoggerName)
	}
	return securityLogger
}

// GetFuncName returns the name of the calling function or code block
func GetFuncName() string {
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	return frame.Function
}

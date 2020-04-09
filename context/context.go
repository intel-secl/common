/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package context

import (
	"context"
	"fmt"
	"net/http"

	types "intel/isecl/lib/common/v2/types/aas"
)

type httpContextKey string

var userRoleKey = httpContextKey("userroles")
var userPermissionKey = httpContextKey("userpermissions")

func SetUserRoles(r *http.Request, val []types.RoleInfo) *http.Request {

	ctx := context.WithValue(r.Context(), "userroles", val)
	return r.WithContext(ctx)
}

func SetUserPermissions(r *http.Request, val []types.PermissionInfo) *http.Request {

	ctx := context.WithValue(r.Context(), "userpermissions", val)
	return r.WithContext(ctx)
}

/*
 func SetUserRoles(r *http.Request, val types.Roles) *http.Request {

	 ctx := context.WithValue(r.Context(), userRoleKey, val)
	 return r.WithContext(ctx)
 }
*/
func GetUserRoles(r *http.Request) ([]types.RoleInfo, error) {
	if rv := r.Context().Value("userroles"); rv != nil {
		if ur, ok := rv.([]types.RoleInfo); ok {
			return ur, nil
		}
	}
	return nil, fmt.Errorf("could not retrieve user roles from context")
}

func GetUserPermissions(r *http.Request) ([]types.PermissionInfo, error) {
	if rv := r.Context().Value("userpermissions"); rv != nil {
		if ur, ok := rv.([]types.PermissionInfo); ok {
			return ur, nil
		}
	}
	return nil, fmt.Errorf("could not retrieve user permissions from context")
}

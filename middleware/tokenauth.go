/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package middleware

import (
	"fmt"
	jwtauth "intel/isecl/lib/common/v2/jwt"
	cos "intel/isecl/lib/common/v2/os"
	ct "intel/isecl/lib/common/v2/types/aas"
	"net/http"

	"intel/isecl/lib/common/v2/context"
	clog "intel/isecl/lib/common/v2/log"
	commLogMsg "intel/isecl/lib/common/v2/log/message"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

var jwtVerifier jwtauth.Verifier
var jwtCertDownloadAttempted bool
var log = clog.GetDefaultLogger()
var slog = clog.GetSecurityLogger()

func initJwtVerifier(signingCertsDir, trustedCAsDir string, cacheTime time.Duration) error {

	certPems, err := cos.GetDirFileContents(signingCertsDir, "*.pem")

	rootPems, err := cos.GetDirFileContents(trustedCAsDir, "*.pem")

	jwtVerifier, err = jwtauth.NewVerifier(certPems, rootPems, cacheTime)

	return err

}

func retrieveAndSaveTrustedJwtSigningCerts() error {
	if jwtCertDownloadAttempted {
		return fmt.Errorf("already attempted to download JWT signing certificates. Will not attempt again")
	}
	// todo. this function will make https requests and save files
	// to the directory where we keep trusted certificates

	jwtCertDownloadAttempted = true
	return nil
}

type RetriveJwtCertFn func() error

func NewTokenAuth(signingCertsDir, trustedCAsDir string, fnGetJwtCerts RetriveJwtCertFn, cacheTime time.Duration) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// pull up the bearer token.

			splitAuthHeader := strings.Split(r.Header.Get("Authorization"), "Bearer ")
			if len(splitAuthHeader) <= 1 {
				log.Error("no bearer token provided for authorization")
				w.WriteHeader(http.StatusUnauthorized)
				slog.Warningf("%s: Invalid token, requested from %s: ", commLogMsg.AuthenticationFailed, r.RemoteAddr)
				return
			}

			// the second item in the slice should be the jwtToken. let try to validate
			claims := ct.AuthClaims{}
			var err error

			// There are two scenarios when we retry the ValidateTokenAndClaims.
			//     1. The cached verifier has expired - could be because the certificate we are using has just expired
			//        or the time has reached when we want to look at the CRL list to make sure the certificate is still
			//        valid.
			//        Error : VerifierExpiredError
			//     2. There are no valid certificates (maybe all are expired) and we need to call the function that retrives
			//        a new certificate. initJwtVerifier takes care of this scenario.

			for needInit, retryNeeded, looped := jwtVerifier == nil, false, false; retryNeeded || !looped; looped = true {

				if needInit || retryNeeded {
					if initErr := initJwtVerifier(signingCertsDir, trustedCAsDir, cacheTime); initErr != nil {
						log.WithError(initErr).Error("attempt to initialize jwt verifier failed")
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					needInit = false
				}
				retryNeeded = false
				_, err = jwtVerifier.ValidateTokenAndGetClaims(strings.TrimSpace(splitAuthHeader[1]), &claims)
				if err != nil && !looped {
					switch err.(type) {
					case *jwtauth.MatchingCertNotFoundError, *jwtauth.MatchingCertJustExpired:
						fnGetJwtCerts()
						retryNeeded = true
					case *jwtauth.VerifierExpiredError:
						retryNeeded = true
					}

				}

			}

			if err != nil {
				// this is a validation failure. Let us log the message and return unauthorized
				log.WithError(err).Error("token validation Failure")
				w.WriteHeader(http.StatusUnauthorized)
				slog.Warningf("%s: Invalid token, requested from %s: ", commLogMsg.AuthenticationFailed, r.RemoteAddr)
				return
			}

			r = context.SetUserRoles(r, claims.Roles)
			r = context.SetUserPermissions(r, claims.Permissions)
			next.ServeHTTP(w, r)
		})
	}
}

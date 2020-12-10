/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"testing"
	"time"
)

func createCert() ([]byte, *rsa.PrivateKey, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"Intel"},
			Country:       []string{"US"},
			Province:      []string{"CA"},
			Locality:      []string{"Folsom"},
			StreetAddress: []string{"1900 Prarie City Rd"},
			PostalCode:    []string{"95630"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	priv, _ := rsa.GenerateKey(rand.Reader, 3072)
	pub := &priv.PublicKey
	cert, _ := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)

	return cert, priv, nil
}

func TestVerifyCertBySha384(t *testing.T) {

	cert, priv, err := createCert()
	if err != nil {
		t.Fatal(err)
	}

	certFile, _ := ioutil.TempFile("", "cert.crt")
	defer os.Remove(certFile.Name())
	keyFile, _ := ioutil.TempFile("", "key.key")
	defer os.Remove(keyFile.Name())
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	certFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyFile.Close()

	http.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bar"))
	})
	go http.ListenAndServeTLS(":1337", certFile.Name(), keyFile.Name(), nil)

	certDigest := sha512.Sum384(cert)
	tlsConfig := tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: VerifyCertBySha384(certDigest),
	} // test code hence skip verify
	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	client := &http.Client{Transport: &transport}
	rsp, err := client.Get("https://localhost:1337/foo")
	if err != nil {
		t.Fatal(err)
	}
	rspBytes, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rspString := string(rspBytes)
	if rspString != "bar" {
		t.Fail()
	}
}

func TestVerifyCertBySha256(t *testing.T) {

	cert, priv, err := createCert()
	if err != nil {
		t.Fatal(err)
	}

	certFile, _ := ioutil.TempFile("", "cert.crt")
	defer os.Remove(certFile.Name())
	keyFile, _ := ioutil.TempFile("", "key.key")
	defer os.Remove(keyFile.Name())
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	certFile.Close()
	pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyFile.Close()

	http.HandleFunc("/foobar", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("bar"))
	})
	go http.ListenAndServeTLS(":1338", certFile.Name(), keyFile.Name(), nil)

	certDigest := sha256.Sum256(cert)
	tlsConfig := tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: VerifyCertBySha256(certDigest),
	} // test code hence skip verify
	transport := http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	client := &http.Client{Transport: &transport}
	rsp, err := client.Get("https://localhost:1338/foobar")
	if err != nil {
		t.Fatal(err)
	}
	rspBytes, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		t.Fatal(err)
	}
	rspString := string(rspBytes)
	if rspString != "bar" {
		t.Fail()
	}
}

func TestGenerateSelfSignCerts(t *testing.T) {

}

func TestGenRSAKeys(t *testing.T) {

}

/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	errorLog "github.com/pkg/errors"
	"intel/isecl/lib/common/v4/crypt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Download_Ca_Cert struct {
	Flags                []string
	CmsBaseURL           string
	CaCertDirPath        string
	TrustedTlsCertDigest string
	ConsoleWriter        io.Writer
}

func DownloadRootCaCertificate(cmsBaseUrl string, dirPath string, trustedTlsCertDigest string) (err error) {
	if !strings.HasSuffix(cmsBaseUrl, "/") {
		cmsBaseUrl = cmsBaseUrl + "/"
	}

	url, err := url.Parse(cmsBaseUrl)
	if err != nil {
		fmt.Println("Configured CMS URL is malformed: ", err)
		return fmt.Errorf("CA certificate setup: %v", err)
	}
	certificates, _ := url.Parse("ca-certificates")
	endpoint := url.ResolveReference(certificates)
	req, err := http.NewRequest("GET", endpoint.String(), nil)
	if err != nil {
		fmt.Println("Failed to instantiate http request to CMS")
		return fmt.Errorf("CA certificate setup: %v", err)
	}
	req.Header.Set("Accept", "application/x-pem-file")
	//InsecureSkipVerify is set to true as connection is validated manually
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true,
			},
			Proxy: http.ProxyFromEnvironment,
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Failed to perform HTTP request to CMS")
		return fmt.Errorf("CA certificate setup: %v", err)
	}
	defer resp.Body.Close()
	// PEM encode the certificate (this is a standard TLS encoding)
	pemBlock := pem.Block{Type: "CERTIFICATE", Bytes: resp.TLS.PeerCertificates[0].Raw}
	certPEM := pem.EncodeToMemory(&pemBlock)
	tlsCertDigest, err := crypt.GetCertHashFromPemInHex(certPEM, crypto.SHA384)
	if err != nil {
		return errorLog.Wrap(err, "setup/download_ca_cert:DownloadRootCaCertificate() CA certificate setup error")
	}
	if resp.StatusCode != http.StatusOK {
		text, _ := ioutil.ReadAll(resp.Body)
		errStr := fmt.Sprintf("CMS request failed to download CA certificate (HTTP Status Code: %d)\nMessage: %s", resp.StatusCode, string(text))
		fmt.Println(errStr)
		return fmt.Errorf("CA certificate setup: %v", err)
	}
	if tlsCertDigest == "" || tlsCertDigest != trustedTlsCertDigest {
		errStr := "CMS TLS Certificate is not trusted"
		return errorLog.Wrap(errors.New(errStr), "setup/download_ca_cert:DownloadRootCaCertificate() CA certificate setup error")
	}
	tlsResp, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Failed to read CMS response body")
		return fmt.Errorf("CA certificate setup: %v", err)
	}
	if tlsResp != nil {
		err = crypt.SavePemCertWithShortSha1FileName(tlsResp, dirPath)
		if err != nil {
			fmt.Println("Could not save CA certificate")
			return fmt.Errorf("CA certificate setup: %v", err)
		}
	} else {
		fmt.Println("Invalid response from Download CA Certificate")
		return fmt.Errorf("Invalid response from Download CA Certificate")
	}
	return nil
}

func (cc Download_Ca_Cert) Run(c Context) error {
	var cmsBaseUrl string
	fmt.Fprintln(cc.ConsoleWriter, "Running CA certificate download setup...")
	fs := flag.NewFlagSet("ca", flag.ContinueOnError)
	force := fs.Bool("force", false, "force recreation, will overwrite any existing certificate")

	err := fs.Parse(cc.Flags)
	if err != nil {
		fmt.Println("CA certificate setup: Unable to parse flags")
		return fmt.Errorf("CA certificate setup: Unable to parse flags")
	}
	if cc.CmsBaseURL != "" {
		cmsBaseUrl = cc.CmsBaseURL
	} else {
		cmsBaseUrl, err = c.GetenvString("CMS_BASE_URL", "CMS base URL in https://{{cms}}:{{cms_port}}/cms/v1/")
		if err != nil || cmsBaseUrl == "" {
			fmt.Println("CMS_BASE_URL not found in environment for Download CA Certificate")
			return fmt.Errorf("CMS_BASE_URL not found in environment for Download CA Certificate")
		}
	}

	if *force || cc.Validate(c) != nil {
		err = DownloadRootCaCertificate(cmsBaseUrl, cc.CaCertDirPath, cc.TrustedTlsCertDigest)
		if err != nil {
			fmt.Println("Failed to Download CA Certificate")
			return err
		}
	} else {
		fmt.Println("CA certificate already downloaded, skipping")
	}
	return nil
}

func (cc Download_Ca_Cert) Validate(c Context) error {
	fmt.Fprintln(cc.ConsoleWriter, "Validating CA certificate download setup...")
	ok, err := IsDirEmpty(cc.CaCertDirPath)
	if err != nil {
		return errors.New("Error opening CA certificate directory")
	}
	if ok == true {
		return errors.New("CA certificate is not downloaded")
	}
	return nil
}

func IsDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}

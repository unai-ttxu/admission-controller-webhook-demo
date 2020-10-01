/*
Copyright (c) 2019 StackRox Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"encoding/json"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/sirupsen/logrus"
	"k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	tlsDir      = `/run/secrets/tls`
	tlsCertFile = `tls.crt`
	tlsKeyFile  = `tls.key`
	tlsCAFile   = "ca.crt"
)

var (
	podResource = metav1.GroupVersionResource{Version: "v1", Resource: "pods"}
	logger      *logrus.Logger
	Version = "development"
)

func applySecurityDefaults(req *v1beta1.AdmissionRequest) ([]patchOperation, error) {
	// This handler should only get called on Pod objects as per the MutatingWebhookConfiguration in the YAML file.
	// However, if (for whatever reason) this gets invoked on an object of a different kind, issue a log message but
	// let the object request pass through otherwise.
	if req.Resource != podResource {
		logger.Infof("Expect resource to be %s", podResource)
		return nil, nil
	}

	// Parse the Pod object.
	raw := req.Object.Raw
	pod := corev1.Pod{}
	if _, _, err := universalDeserializer.Decode(raw, nil, &pod); err != nil {
		logger.Errorf("Could not deserialize pod object: %v", err)
		return nil, err
	}

	// Retrieve the vaultRole value from annotation with key "appRole.stratio.com".
	vaultRole := pod.Annotations["appRole.stratio.com"]

	// Vault Response structure (must have underscore)
	type Data struct {
		Role_id   string
		Secret_id string
	}

	type Response struct {
		Data Data
	}

	var roleData Response
	var secretData Response
	var patches []patchOperation

	if vaultRole != "" {

		logger.Debugf("Using vaultRole %s", vaultRole)

		// Getting the role_id
		logger.Info("Getting Role ID ...")
		roleResponse, _ := getVaultData("GET", "/v1/auth/approle/role/"+vaultRole+"/role-id")
		json.Unmarshal(roleResponse, &roleData)
		logger.Debugf("Role_id: %s\n", roleData.Data.Role_id)

        if roleData.Data.Role_id == "" {
            logger.Error("Error Role_Id is blank")
            return nil, errors.New("Error Role_Id is blank")
        }

		// Create jsonpatch operations
		for i, container := range pod.Spec.Containers {
			logger.Debugf("Container name: %s\n", container.Name)
			logger.Debugf("Container index: %d\n", i)

			// Getting the secret_id
			logger.Info("Getting Secret ID ...")
			secretResponse, _ := getVaultData("POST", "/v1/auth/approle/role/"+vaultRole+"/secret-id")
			json.Unmarshal(secretResponse, &secretData)
			logger.Debugf("Secret_id: %s\n", secretData.Data.Secret_id)

            if secretData.Data.Secret_id == "" {
                logger.Error("Error Secret_Id is blank")
                return nil, errors.New("Error Secret_Id is blank")
            }

			if container.Env == nil {
				// Improvement: Create an empty env array only when there's no env
				// and always add both elements

				var roleMap map[string]string
				roleMap = make(map[string]string)
				roleMap["name"] = "VAULT_ROLE_ID"
				roleMap["value"] = roleData.Data.Role_id

				var secretMap map[string]string
				secretMap = make(map[string]string)
				secretMap["name"] = "VAULT_SECRET_ID"
				secretMap["value"] = secretData.Data.Secret_id

				var envDir []map[string]string
				envDir = append(envDir, roleMap)
				envDir = append(envDir, secretMap)

				patches = append(patches, patchOperation{
					Op:    "add",
					Path:  "/spec/containers/" + strconv.Itoa(i) + "/env",
					Value: envDir,
				})
			} else {

				var roleMap map[string]string
				roleMap = make(map[string]string)
				roleMap["name"] = "VAULT_ROLE_ID"
				roleMap["value"] = roleData.Data.Role_id

				patches = append(patches, patchOperation{
					Op:    "add",
					Path:  "/spec/containers/" + strconv.Itoa(i) + "/env/0",
					Value: roleMap,
				})

				var secretMap map[string]string
				secretMap = make(map[string]string)
				secretMap["name"] = "VAULT_SECRET_ID"
				secretMap["value"] = secretData.Data.Secret_id

				patches = append(patches, patchOperation{
					Op:    "add",
					Path:  "/spec/containers/" + strconv.Itoa(i) + "/env/1",
					Value: secretMap,
				})
			}
		}
	}

	return patches, nil
}

func getVaultData(method string, path string) ([]byte, error) {

	vaultToken := os.Getenv("VAULT_TOKEN")
	vaultAddress := "https://" + os.Getenv("VAULT_HOSTS") + ":" + os.Getenv("VAULT_PORT")

	// Load client cert
	certPath := filepath.Join(tlsDir, tlsCertFile)
	keyPath := filepath.Join(tlsDir, tlsKeyFile)

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		logger.Fatal(err)
	}

	// Prepare client
	req, err := http.NewRequest(method, vaultAddress+path, nil)
	if err != nil {
		logger.Fatalf("Error reading request: %v", err)
	}

	req.Header.Set("X-Vault-Token", vaultToken)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{cert},
			},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		logger.Fatalf("Error reading response: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Fatalf("Error reading body: %v", err)
	}

	return body, nil
}

func getClientValidator(helloInfo *tls.ClientHelloInfo, rootCAs *x509.CertPool) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

		// Pass only if the client's CN is in commonName list

		// WARNING: Dont' forget to update the list lenght ;)
		var commonNames = [1]string{os.Getenv("ADMISSION_CONTROL_CN")}
		var err error

		// Verify certificate expiration
		opts := x509.VerifyOptions{
			Roots: rootCAs,
		}
		_, err = verifiedChains[0][0].Verify(opts)
		if err != nil {
			logger.Errorf("Invalid client's Certificate: %v", err)
			return err
		}

		for _, commonName := range commonNames {
			logger.Debugf("CommonName: %s", commonName)

			// Verify certificate's CN
			err = verifiedChains[0][0].VerifyHostname(commonName)
			if err == nil {
				return nil
			}
	}
		logger.Error("Invalid client's CN")
		return errors.New("Invalid client's CN")
	}
}

func main() {

	// Setting up logger

	f := Formatter{}

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "INFO"
	}
	logrusLevel, _ := logrus.ParseLevel(logLevel)

	logger = &logrus.Logger{
		Out:       os.Stdout,
		Level:     logrusLevel,
		Formatter: &f,
	}

	logger.Infof("Starting up Admission Controller v %s", Version)

	certPath := filepath.Join(tlsDir, tlsCertFile)
	keyPath := filepath.Join(tlsDir, tlsKeyFile)
	caPath := filepath.Join(tlsDir, tlsCAFile)

	mux := http.NewServeMux()
	mux.Handle("/mutate", admitFuncHandler(applySecurityDefaults))

	// TLS whitelisting

	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		logger.Error(err)
		return
	}

	caCert, err := ioutil.ReadFile(caPath)
	if err != nil {
		logger.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cer},
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			serverConf := &tls.Config{
				Certificates:          []tls.Certificate{cer},
				MinVersion:            tls.VersionTLS12,
				ClientAuth:            tls.RequireAndVerifyClientCert,
				ClientCAs:             caCertPool,
				VerifyPeerCertificate: getClientValidator(hi, caCertPool),
			}
			return serverConf, nil
		},
	}

	server := &http.Server{
		Addr:      ":8443",
		Handler:   mux,
		TLSConfig: cfg,
	}
	logger.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}

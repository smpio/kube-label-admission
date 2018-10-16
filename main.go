package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return strings.Join(*i, ",")
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var scheme = runtime.NewScheme()
var codecs = serializer.NewCodecFactory(scheme)
var protectedLabel string
var allowedUsers arrayFlags
var objKind metav1.GroupVersionKind

func init() {
	corev1.AddToScheme(scheme)
	admissionregistrationv1beta1.AddToScheme(scheme)
}

func main() {
	var CertFile string
	var KeyFile string

	flag.StringVar(&CertFile, "tls-cert-file", CertFile, ""+
		"File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated "+
		"after server cert).")
	flag.StringVar(&KeyFile, "tls-key-file", KeyFile, ""+
		"File containing the default x509 private key matching --tls-cert-file.")
	// flag.StringVar(&objKind.Group, "obj-api-group", objKind.Group, ""+
	// 	"API group of objects to watch (may be empty string, \"extensions\", \"apps\", etc).")
	// flag.StringVar(&objKind.Version, "obj-api-version", objKind.Version, ""+
	// 	"API group version of objects to watch (e.g. \"v1\").")
	// flag.StringVar(&objKind.Kind, "obj-kind", objKind.Kind, ""+
	// 	"Kind of objects to watch (e.g. \"Namespace\", \"Pod\").")
	flag.StringVar(&protectedLabel, "protected-label", protectedLabel, ""+
		"Object label that only specified users can set.")
	flag.Var(&allowedUsers, "allow-user", ""+
		"Username that is allowed to set protected label (may be specified multiple times).")

	flag.Parse()

	http.HandleFunc("/", mkServe())
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: configTLS(CertFile, KeyFile),
	}
	server.ListenAndServeTLS("", "")

}

func configTLS(CertFile string, KeyFile string) *tls.Config {
	sCert, err := tls.LoadX509KeyPair(CertFile, KeyFile)
	if err != nil {
		log.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{sCert},
	}
}

func mkServe() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Body != nil {
			if data, err := ioutil.ReadAll(r.Body); err == nil {
				body = data
			}
		}

		// verify the content type is accurate
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			log.Printf("contentType=%s, expect application/json", contentType)
			return
		}

		var reviewResponse *v1beta1.AdmissionResponse
		ar := v1beta1.AdmissionReview{}
		deserializer := codecs.UniversalDeserializer()
		if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
			log.Print(err)
			reviewResponse = toAdmissionResponse(err)
		} else {
			reviewResponse = admit(ar)
		}

		response := v1beta1.AdmissionReview{}
		if reviewResponse != nil {
			response.Response = reviewResponse
			response.Response.UID = ar.Request.UID
		}
		// reset the Object and OldObject, they are not needed in a response.
		ar.Request.Object = runtime.RawExtension{}
		ar.Request.OldObject = runtime.RawExtension{}

		resp, err := json.Marshal(response)
		if err != nil {
			log.Print(err)
		}
		if _, err := w.Write(resp); err != nil {
			log.Print(err)
		}
	}
}

func toAdmissionResponse(err error) *v1beta1.AdmissionResponse {
	return &v1beta1.AdmissionResponse{
		Result: &metav1.Status{
			Message: err.Error(),
		},
	}
}

func admit(ar v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	reviewResponse := v1beta1.AdmissionResponse{}
	reviewResponse.Allowed = true

	if !isUserAllowed(ar.Request.UserInfo.Username) {
		if ar.Request.Operation != "CREATE" && ar.Request.Operation != "UPDATE" {
			err := errors.New("expected operation to be CREATE or UPDATE")
			log.Print(err)
			return toAdmissionResponse(err)
		}

		meta := struct {
			metav1.ObjectMeta `json:"metadata,omitempty"`
		}{}

		if err := json.Unmarshal(ar.Request.Object.Raw, &meta); err != nil {
			log.Print(err)
			return toAdmissionResponse(err)
		}

		for k := range meta.Labels {
			if k == protectedLabel {
				reviewResponse.Allowed = false
				reviewResponse.Result = &metav1.Status{
					Message: fmt.Sprintf("label %s is protected", protectedLabel),
				}
				break
			}
		}
	}

	return &reviewResponse
}

func isUserAllowed(username string) bool {
	for _, allowed := range allowedUsers {
		if username == allowed {
			return true
		}
	}
	return false
}

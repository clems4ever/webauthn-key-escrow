package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/gorilla/mux"
	uuid "github.com/satori/go.uuid"
)

var registerTemplate *template.Template
var loginTemplate *template.Template

func init() {
	var err error
	registerTemplate = template.Must(template.ParseFS(content, "templates/register.html"))
	if err != nil {
		log.Fatalf("error parsing template: %s", err)
	}

	loginTemplate = template.Must(template.ParseFS(content, "templates/login.html"))
	if err != nil {
		log.Fatalf("error parsing template: %s", err)
	}
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	kid, ok := vars["kid"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid kid"), http.StatusBadRequest)
		return
	}
	err := registerTemplate.Execute(w, struct {
		Kid string
	}{
		Kid: kid,
	})
	if err != nil {
		log.Fatalf("error executing template: %s", err)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	transaction, ok := vars["transaction"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid kid"), http.StatusBadRequest)
		return
	}
	err := loginTemplate.Execute(w, struct {
		Transaction string
	}{
		Transaction: transaction,
	})
	if err != nil {
		log.Fatalf("error executing template: %s", err)
	}
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	kid, ok := vars["kid"]
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid kid"), http.StatusBadRequest)
		return
	}

	key, err := keyDB.GetKey(kid)
	// key doesn't exist, create new key
	if err != nil {
		key = NewKey(kid)
		keyDB.PutKey(key)
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = key.CredentialExcludeList()
	}

	// generate PublicKeyCredentialCreationOptions, session data
	options, sessionData, err := webAuthn.BeginRegistration(
		key,
		registerOptions,
	)

	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	kid := vars["kid"]

	key, err := keyDB.GetKey(kid)
	// key doesn't exist
	if err != nil {
		log.Printf("unable to get key: %s\n", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("registration", r)
	if err != nil {
		log.Printf("unable to load session data: %s\n", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	credential, err := webAuthn.FinishRegistration(key, sessionData, r)
	if err != nil {
		log.Printf("unable to finish registration: %s\n", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	key.AddCredential(*credential)

	jsonResponse(w, "Registration Success", http.StatusOK)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	transactionQueryParm := vars["transaction"]

	transaction, ok := transactions[transactionQueryParm]
	if !ok {
		jsonResponse(w, "transaction does not exist", http.StatusBadRequest)
		return
	}

	key, err := keyDB.GetKey(transaction.kid)

	// key doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData, err := webAuthn.BeginLogin(key)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, options, http.StatusOK)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	transactionQueryParm := vars["transaction"]

	transaction, ok := transactions[transactionQueryParm]
	if !ok {
		jsonResponse(w, "transaction does not exist", http.StatusBadRequest)
		return
	}

	key, err := keyDB.GetKey(transaction.kid)

	// key doesn't exist
	if err != nil {
		log.Printf("unable to get key: %s\n", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// load the session data
	sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
	if err != nil {
		log.Printf("unable to get webauthn session: %s\n", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_, err = webAuthn.FinishLogin(key, sessionData, r)
	if err != nil {
		log.Printf("unable to finish login: %s\n", err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	transaction.completeQ <- struct{}{}

	// handle successful login
	jsonResponse(w, "Login Success", http.StatusOK)
}

func GetKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	kid := vars["kid"]

	key, err := keyDB.GetKey(kid)

	// key doesn't exist
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	id := uuid.NewV4()
	transactionKey := id.String()

	transaction := Transaction{
		kid:       kid,
		completeQ: make(chan struct{}),
	}
	transactions[transactionKey] = transaction

	/*err = sessionStore.Set(transactionKey, transaction, r, w)
	if err != nil {
		log.Println(err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}*/

	notify(domain, transactionKey)

	select {
	// the transaction has completed, we can give the key
	case <-transaction.completeQ:
		jsonResponse(w, key.content, http.StatusOK)
	case <-r.Context().Done():
		jsonResponse(w, "Request timeout", http.StatusRequestTimeout)
	}
}

func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}

package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
)

var webAuthn *webauthn.WebAuthn
var keyDB *keydb
var sessionStore *Store
var transactions map[string]Transaction = make(map[string]Transaction)
var domain = "localhost"

//go:embed templates/*.html
var content embed.FS

func main() {
	var err error
	webAuthn, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "Foobar Corp.",                        // Display Name for your site
		RPID:          domain,                                // Generally the domain name for your site
		RPOrigin:      fmt.Sprintf("http://%s:8080", domain), // The origin URL for WebAuthn requests
		// RPIcon: "https://duo.com/logo.png", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("failed to create WebAuthn from config:", err)
	}

	keyDB = DB()

	sessionStore, err = NewStore()
	if err != nil {
		log.Fatal("failed to create session store:", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/{kid}", RegisterHandler)
	r.HandleFunc("/register/begin/{kid}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{kid}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/{transaction}", LoginHandler)
	r.HandleFunc("/login/begin/{transaction}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{transaction}", FinishLogin).Methods("POST")
	r.HandleFunc("/keys/{kid}", GetKey).Methods("GET")

	serverAddress := ":8080"
	log.Println("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))
}

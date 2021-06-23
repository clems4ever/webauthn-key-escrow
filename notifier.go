package main

import "fmt"

func notify(domain string, transaction string) {
	fmt.Printf("http://%s:8080/login/%s\n", domain, transaction)
}

package main

type Transaction struct {
	kid       string
	completeQ chan struct{}
}

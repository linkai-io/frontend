package main

import (
	"flag"
)

var (
	env string 
	
)

func init() {
	flag.StringVar(&env, "env", "dev", "environment to run cli against")
}

func main() {

}
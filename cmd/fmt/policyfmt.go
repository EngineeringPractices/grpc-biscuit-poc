package main

import (
	"demo/pkg/policy"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

var (
	write = flag.Bool("w", false, "write result to (source) file instead of stdout")
)

func main() {
	log.SetFlags(0)
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatalf("require file")
	}

	filename := flag.Arg(0)
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("failed to read file: %v", err)
	}

	out, err := policy.Print(filename, strings.NewReader(string(f)))
	if err != nil {
		log.Fatalf("failed to print policies: %v", err)
	}

	if *write {
		if err := ioutil.WriteFile(filename, []byte(out), 0644); err != nil {
			log.Fatalf("failed to write file: %v", err)
		}
	} else {
		fmt.Println(out)
	}
}

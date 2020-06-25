// Copyright 2018 The go-ego Project Developers.
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// package tcpp packet tools

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/vcaesar/tcpp/find"
)

var (
	expr string
	pc   find.Pacp

	device  = flag.String("i", "", "devices")        // device: en0,bond0
	ofile   = flag.String("d", "", "dump file path") // gen dump file
	read    = flag.String("r", "", "read dump file") // read dump file
	snaplen = flag.Int("s", 1024, "snaplen")

	help    = flag.Bool("h", false, "help")
	count   = flag.String("c", "", "capture count of the dump line")
	timeout = flag.String("t", "", "timeout")
)

func fg() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr,
			"usage: %s \n [ -i devices ] \n [ -t timeout ] \n [ -c count ] \n [ -s snaplen ] \n [ -d dump file ] \n [ -r read file ] \n [ -h show usage] \n [ expression ] \n", os.Args[0])
		os.Exit(1)
	}

	flag.Parse()

	if len(flag.Args()) > 0 {
		expr = flag.Arg(0)
	}

	if *help {
		flag.Usage()
	}
}

func main() {
	fg()

	if *read != "" {
		src := *read
		var err error

		pc.H, err = pc.Open(src)
		defer pc.H.Close()
		if err != nil {
			log.Println("tccp read hand error is: ", err)
		}

		pc.Decode(expr)
		return
	}

	if *device == "" {
		devs, err := pc.FindAllDevs()
		if err != nil {
			fmt.Fprintln(os.Stderr, "tcpp: couldn't find any devices:", err)
		}

		if 0 == len(devs) {
			flag.Usage()
		}
		*device = devs[0].Name
	}

	pc.Device = *device
	pc.Snaplen = *snaplen
	// pc.Promiscuous = true
	pc.Timeout = 50 * time.Second

	var err error
	pc.H, err = pc.ReadFilter(expr)
	defer pc.H.Close()
	if err != nil {
		log.Println("tccp read hand error is: ", err)
	}

	cs := *count
	pc.Count = 1
	if cs != "" {
		var err error
		pc.Count, err = strconv.Atoi(cs)
		if err != nil {
			pc.Count = 1
		}
	}

	if *ofile != "" {
		pc.Write(*ofile)
	}

	ts := *timeout
	if ts != "" {
		t, err := strconv.Atoi(ts)
		if err == nil {
			pc.Timeout = time.Second * time.Duration(t)
		}
	}

	pc.Decode(expr)
}

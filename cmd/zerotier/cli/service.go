/*
 * Copyright (c)2013-2020 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2024-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"strconv"
	"syscall"

	"zerotier/pkg/zerotier"
)

func Service(basePath, authToken string, args []string) {
	if len(args) > 0 {
		Help()
		os.Exit(1)
	}

	pidPath := path.Join(basePath, "zerotier.pid")
	_ = ioutil.WriteFile(pidPath, []byte(strconv.FormatInt(int64(os.Getpid()), 10)), 0644)

	node, err := zerotier.NewNode(basePath)
	if err != nil {
		fmt.Println("FATAL: error initializing node: " + err.Error())
	} else {
		osSignalChannel := make(chan os.Signal, 2)
		signal.Notify(osSignalChannel, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGSTOP)
		signal.Ignore(syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGPIPE, syscall.SIGHUP)
		<-osSignalChannel
		node.Close()
	}

	_ = os.Remove(pidPath)
	os.Exit(1)
}
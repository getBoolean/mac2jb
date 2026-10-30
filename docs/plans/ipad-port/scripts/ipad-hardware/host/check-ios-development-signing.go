// Classify local iOS development signing inputs without printing identities.
//
// This Mac-only program asks Security for valid code-signing identities and
// checks the two Xcode provisioning-profile directories. It reports only
// presence categories; names, team IDs, hashes, profiles, and device IDs stay
// private. It never contacts or changes the iPad or the keychain.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func category(value bool) string {
	if value {
		return "present"
	}
	return "absent"
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/security", "find-identity", "-p", "codesigning", "-v")
	output, err := command.Output()
	if err != nil || len(output) > 65536 || ctx.Err() != nil {
		fmt.Println("SIGNING_CAPABILITY query=unavailable")
		return
	}
	development := false
	distribution := false
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, `"Apple Development:`) || strings.Contains(line, `"iPhone Developer:`) {
			development = true
		}
		if strings.Contains(line, `"Apple Distribution:`) || strings.Contains(line, `"iPhone Distribution:`) {
			distribution = true
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("SIGNING_CAPABILITY query=unavailable")
		return
	}
	profile := false
	for _, relative := range []string{
		"Library/MobileDevice/Provisioning Profiles",
		"Library/Developer/Xcode/UserData/Provisioning Profiles",
	} {
		entries, err := os.ReadDir(filepath.Join(home, relative))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || len(entries) > 4096 {
			fmt.Println("SIGNING_CAPABILITY query=unavailable")
			return
		}
		for _, entry := range entries {
			if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".mobileprovision") {
				profile = true
			}
		}
	}
	fmt.Printf("SIGNING_CAPABILITY query=ok development=%s distribution=%s profile-files=%s\n",
		category(development), category(distribution), category(profile))
}

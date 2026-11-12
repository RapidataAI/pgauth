package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const serviceLabel = "dev.pgauth.connect"

// serviceCmd installs `pgauth connect` as a per-user service: a launchd agent on macOS, a systemd
// user unit on Linux.
func serviceCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: pgauth service install|uninstall [--config file]")
	}
	fs := flag.NewFlagSet("service "+args[0], flag.ExitOnError)
	path := fs.String("config", "", "connect.yaml the service uses")
	_ = fs.Parse(args[1:])
	cfg, err := filepath.Abs(configPath(*path))
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	switch runtime.GOOS + " " + args[0] {
	case "darwin install":
		plist := filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist")
		logFile := filepath.Join(home, "Library", "Logs", "pgauth-connect.log")
		if err := writeFile(plist, launchdPlist(exe, cfg, logFile)); err != nil {
			return err
		}
		domain := "gui/" + strconv.Itoa(os.Getuid())
		_ = exec.Command("launchctl", "bootout", domain+"/"+serviceLabel).Run()
		if err := run("launchctl", "bootstrap", domain, plist); err != nil {
			return err
		}
		fmt.Printf("installed %s; logs in %s\n", plist, logFile)
	case "darwin uninstall":
		_ = exec.Command("launchctl", "bootout", "gui/"+strconv.Itoa(os.Getuid())+"/"+serviceLabel).Run()
		return removeFile(filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist"))
	case "linux install":
		unit := filepath.Join(home, ".config", "systemd", "user", "pgauth-connect.service")
		if err := writeFile(unit, systemdUnit(exe, cfg)); err != nil {
			return err
		}
		if err := run("systemctl", "--user", "daemon-reload"); err != nil {
			return err
		}
		if err := run("systemctl", "--user", "enable", "--now", "pgauth-connect.service"); err != nil {
			return err
		}
		fmt.Printf("installed %s; logs: journalctl --user -u pgauth-connect\n", unit)
	case "linux uninstall":
		_ = exec.Command("systemctl", "--user", "disable", "--now", "pgauth-connect.service").Run()
		if err := removeFile(filepath.Join(home, ".config", "systemd", "user", "pgauth-connect.service")); err != nil {
			return err
		}
		return run("systemctl", "--user", "daemon-reload")
	default:
		return fmt.Errorf("pgauth service %s is not supported on %s", args[0], runtime.GOOS)
	}
	return nil
}

func launchdPlist(exe, cfg, logFile string) string {
	esc := func(s string) string {
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + serviceLabel + `</string>
  <key>ProgramArguments</key>
  <array><string>` + esc(exe) + `</string><string>connect</string><string>--config</string><string>` + esc(cfg) + `</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>` + esc(logFile) + `</string>
</dict>
</plist>
`
}

func systemdUnit(exe, cfg string) string {
	return `[Unit]
Description=pgauth connect: local Postgres access through pgauth

[Service]
ExecStart=` + strconv.Quote(exe) + ` connect --config ` + strconv.Quote(cfg) + `
Restart=on-failure

[Install]
WantedBy=default.target
`
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func removeFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RapidataAI/pgauth/internal/config"
	"github.com/RapidataAI/pgauth/internal/rbac"
)

// lint checks access rules offline: it reads only the config file and the YAML, never the files
// the config points to, and makes no network calls. It returns the exit code.
func lint(args []string) int {
	fs := flag.NewFlagSet("lint", flag.ExitOnError)
	path := fs.String("config", "", "serve config; enables the instance, database and generated-role checks")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: pgauth lint [--config <file>] <dir>")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	var instances rbac.Instances
	if *path != "" {
		cfg, err := config.Load(*path)
		if err != nil {
			fmt.Fprintln(os.Stderr, *path+":", err)
			return 1
		}
		instances = cfg.Databases()
	}
	files, err := rbac.ReadDir(fs.Arg(0))
	if err == nil {
		_, err = os.Stat(fs.Arg(0))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	res, errs := rbac.Parse(files)
	if len(errs) == 0 {
		_, errs = rbac.Compile(res, instances)
	}
	for _, e := range errs {
		fmt.Println(e)
	}
	if len(errs) > 0 {
		return 1
	}
	fmt.Printf("ok: %d PgRole, %d PgRoleBinding in %d files\n", len(res.Roles), len(res.Bindings), len(files))
	return 0
}

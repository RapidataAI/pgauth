package main

import (
	"reflect"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/RapidataAI/pgauth/internal/connect"
)

func TestListeners(t *testing.T) {
	tests := []struct {
		name               string
		file               string
		flagListen, flagIn string
		want               []connect.Listener
	}{
		{"v0.3 config with top-level listen", "listen: 127.0.0.1:5432\n", "", "",
			[]connect.Listener{{Listen: "127.0.0.1:5432"}}},
		{"listeners per instance", "listeners:\n  - {listen: 127.0.0.1:15432, instance: cloudsql-main}\n  - {listen: 127.0.0.1:15433, instance: bidder}\n", "", "",
			[]connect.Listener{{Listen: "127.0.0.1:15432", Instance: "cloudsql-main"}, {Listen: "127.0.0.1:15433", Instance: "bidder"}}},
		{"listeners plus top-level listen", "listen: 127.0.0.1:5432\nlisteners: [{listen: 127.0.0.1:15432, instance: cloudsql-main}]\n", "", "",
			[]connect.Listener{{Listen: "127.0.0.1:15432", Instance: "cloudsql-main"}, {Listen: "127.0.0.1:5432"}}},
		{"--listen replaces the file", "listeners: [{listen: 127.0.0.1:15432, instance: cloudsql-main}]\n", "127.0.0.1:6000", "bidder",
			[]connect.Listener{{Listen: "127.0.0.1:6000", Instance: "bidder"}}},
		{"nothing set", "", "", "",
			[]connect.Listener{{Listen: "127.0.0.1:5432"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f connectFile
			if err := yaml.UnmarshalStrict([]byte(tt.file), &f); err != nil {
				t.Fatal(err)
			}
			if got := listeners(tt.flagListen, tt.flagIn, f); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

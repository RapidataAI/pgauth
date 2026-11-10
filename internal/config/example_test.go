package config

import "testing"

func TestExampleLoads(t *testing.T) {
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Instances[0].Port != 5432 || c.Group("reader", "orders") != "orders_read" {
		t.Fatalf("%+v", c)
	}
}

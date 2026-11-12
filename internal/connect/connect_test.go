package connect

import "testing"

func TestTargetDatabase(t *testing.T) {
	tests := []struct{ instance, db, want string }{
		{"cloudsql-main", "order", "cloudsql-main/order"},
		{"cloudsql-main", "cloudsql-main/order", "cloudsql-main/order"},
		{"cloudsql-main", "bidder/bids", "bidder/bids"},
		{"cloudsql-main", "", ""},
		{"", "order", "order"},
		{"", "cloudsql-main/order", "cloudsql-main/order"},
	}
	for _, tt := range tests {
		if got := TargetDatabase(tt.instance, tt.db); got != tt.want {
			t.Errorf("TargetDatabase(%q, %q) = %q, want %q", tt.instance, tt.db, got, tt.want)
		}
	}
}

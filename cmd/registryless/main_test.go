package main

import "testing"

func TestByteQuantity(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int64
	}{
		{"10Mi", 10485760}, {"10M", 10000000}, {"10485760", 10485760}, {"1.048576e+07", 10485760}, {"1.5Mi", 1572864},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Setenv("RATE", tc.input)
			got, err := byteQuantity("RATE", "10Mi")
			if err != nil || got != tc.want {
				t.Fatalf("got %d, %v; want %d", got, err, tc.want)
			}
		})
	}
	for _, input := range []string{"0", "-10Mi", "garbage", ""} {
		t.Run("invalid-"+input, func(t *testing.T) {
			t.Setenv("RATE", input)
			if _, err := byteQuantity("RATE", "10Mi"); err == nil {
				t.Fatal("accepted invalid rate")
			}
		})
	}
}

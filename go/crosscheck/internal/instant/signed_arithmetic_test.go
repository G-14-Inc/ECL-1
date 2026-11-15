package instant

import (
	"math"
	"math/big"
	"testing"
)

func asNanoseconds(i Instant) *big.Int {
	return new(big.Int).Add(new(big.Int).Mul(big.NewInt(i.Seconds), big.NewInt(1_000_000_000)), big.NewInt(i.Nanos))
}

func TestSignedNanosecondNormalization(t *testing.T) {
	i, _ := Parse("2026-11-10T12:00:01.100000000Z")
	for _, delta := range []int64{math.MinInt64, -1_500_000_001, -500_000_000, -1, 0, 1, 900_000_000, math.MaxInt64} {
		got := i.AddNanoseconds(delta)
		want := new(big.Int).Add(asNanoseconds(i), big.NewInt(delta))
		if got.Nanos < 0 || got.Nanos >= 1_000_000_000 || asNanoseconds(got).Cmp(want) != 0 {
			t.Errorf("delta %d: got %+v, want %s ns", delta, got, want)
		}
	}
}

func TestMillisecondsAvoidIntermediateOverflow(t *testing.T) {
	for _, text := range []string{"0001-01-01T00:00:00Z", "1969-12-31T23:59:59.999999999Z", "2026-11-10T12:00:00.100000000Z", "9999-12-31T23:59:59.999999999Z"} {
		i, err := Parse(text)
		if err != nil {
			t.Fatal(err)
		}
		for _, delta := range []int64{math.MinInt64, -9_007_199_254_740_991, -1000, -999, -1, 0, 1, 999, 1000, 9_007_199_254_740_991, math.MaxInt64} {
			got := i.AddMilliseconds(delta)
			want := new(big.Int).Add(asNanoseconds(i), new(big.Int).Mul(big.NewInt(delta), big.NewInt(1_000_000)))
			if got.Nanos < 0 || got.Nanos >= 1_000_000_000 || asNanoseconds(got).Cmp(want) != 0 {
				t.Errorf("%s + %d ms: got %+v, want %s ns", text, delta, got, want)
			}
		}
	}
}

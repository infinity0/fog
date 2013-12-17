package main

import "testing"

import "git.torproject.org/pluggable-transports/goptlib.git"

func TestEncodeServerTransportOptions(t *testing.T) {
	tests := [...]struct {
		methodName string
		opts       pt.Args
		expected   string
	}{
		{
			"foo",
			pt.Args{},
			"",
		},
		{
			"foo",
			pt.Args{
				"key": []string{"value1", "value2"},
				"something": []string{"value1", "value2"},
			},
			"foo:key=value1;foo:key=value2;foo:something=value1;foo:something=value2",
		},
		{
			"m:m",
			pt.Args{"k;k": []string{"v=v", "b\\b"}},
			"m\\:m:k\\;k=v\\=v;m\\:m:k\\;k=b\\\\b",
		},
	}

	for _, test := range tests {
		output := encodeServerTransportOptions(test.methodName, test.opts)
		if output != test.expected {
			t.Errorf("%q %q → %q (expected %q)", test.methodName, test.opts, output, test.expected)
		}
	}
}

package setup

import (
	"reflect"
	"testing"

	"github.com/ldsec/helium/pkg/pkg"
)

func TestMergeSetupDescriptions(t *testing.T) {
	type args struct {
		sd1 Description
		sd2 Description
	}
	tests := []struct {
		name      string
		args      args
		wantSdOut Description
	}{
		{name: "null",
			args:      args{sd1: Description{}, sd2: Description{}},
			wantSdOut: Description{}},
		{name: "cpk-1",
			args:      args{sd1: Description{Cpk: []pkg.NodeID{"n1"}}, sd2: Description{}},
			wantSdOut: Description{Cpk: []pkg.NodeID{"n1"}}},
		{name: "cpk-2",
			args:      args{sd1: Description{}, sd2: Description{Cpk: []pkg.NodeID{"n1"}}},
			wantSdOut: Description{Cpk: []pkg.NodeID{"n1"}}},
		{name: "cpk-1-2",
			args:      args{sd1: Description{Cpk: []pkg.NodeID{"n1"}}, sd2: Description{Cpk: []pkg.NodeID{"n2"}}},
			wantSdOut: Description{Cpk: []pkg.NodeID{"n1", "n2"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotSdOut := MergeSetupDescriptions(tt.args.sd1, tt.args.sd2); !reflect.DeepEqual(gotSdOut, tt.wantSdOut) {
				t.Errorf("MergeSetupDescriptions() = %v, want %v", gotSdOut, tt.wantSdOut)
			}
		})
	}
}

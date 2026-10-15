/*
Merlin is a post-exploitation command and control framework.
This file is part of Merlin.
Copyright (C) 2023  Russel Van Tuyl

Merlin is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

Merlin is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Merlin.  If not, see <http://www.gnu.org/licenses/>.
*/

package sharpgen

import (
	"path/filepath"
	"testing"
)

// TestSharpGenToolPaths_Pinned verifies that the dotnet executable and the SharpGen compiler DLL
// are pinned to fixed, server-side locations derived only from the Merlin root. This is the
// remediation for GHSA-gmq6-43v4-9vrv: these two values must never be influenced by
// operator-supplied input, otherwise exec.Command would run an arbitrary binary on the teamserver.
func TestSharpGenToolPaths_Pinned(t *testing.T) {
	const root = "/opt/merlin"

	dotNetBin, sharpGenBin := sharpGenToolPaths(root)

	if dotNetBin != "dotnet" {
		t.Errorf("dotNetBin = %q, want %q", dotNetBin, "dotnet")
	}

	want := filepath.Join(root, "data", "src", "cobbr", "SharpGen", "bin", "release", "netcoreapp2.1", "SharpGen.dll")
	if sharpGenBin != want {
		t.Errorf("sharpGenBin = %q, want %q", sharpGenBin, want)
	}
}

// TestSharpGenToolPaths_IndependentOfOperatorInput is a regression guard proving the tool paths are
// a pure function of the Merlin root: the same root always yields the same paths, so there is no
// operator-controlled option that can redirect the executable or its first argument. A malicious
// "dotnetbin"/"sharpgenbin" value (e.g. /bin/bash + an uploaded script) cannot reach exec.Command.
func TestSharpGenToolPaths_IndependentOfOperatorInput(t *testing.T) {
	// Values an attacker would supply via the gRPC module options. They are deliberately NOT inputs
	// to sharpGenToolPaths, so they cannot change its output.
	for _, root := range []string{"/opt/merlin", "/home/operator/merlin", "."} {
		dotNetBin, sharpGenBin := sharpGenToolPaths(root)
		if dotNetBin == "/bin/bash" || filepath.Base(sharpGenBin) != "SharpGen.dll" {
			t.Errorf("tool paths for root %q were influenced away from their pinned values: dotnet=%q sharpgen=%q", root, dotNetBin, sharpGenBin)
		}
	}
}

// TestSetDotNetBin verifies the server operator can override the dotnet executable path (the
// -dotnetBin launch flag) while the SharpGen DLL stays pinned under the Merlin root. This is a
// server-launch setting, not a gRPC option, so it does not reintroduce GHSA-gmq6-43v4-9vrv.
func TestSetDotNetBin(t *testing.T) {
	defer SetDotNetBin("dotnet") // restore the package default for other tests
	dotNetBin = "dotnet"

	// An empty override is ignored; the default is retained.
	SetDotNetBin("")
	if dotnet, _ := sharpGenToolPaths("/opt/merlin"); dotnet != "dotnet" {
		t.Errorf(`after SetDotNetBin(""), dotnet = %q, want "dotnet"`, dotnet)
	}

	// A non-empty override is applied; the SharpGen DLL remains pinned under the Merlin root.
	const custom = "/usr/local/dotnet/dotnet"
	SetDotNetBin(custom)
	dotnet, sharpgen := sharpGenToolPaths("/opt/merlin")
	if dotnet != custom {
		t.Errorf("after SetDotNetBin(%q), dotnet = %q, want %q", custom, dotnet, custom)
	}
	if filepath.Base(sharpgen) != "SharpGen.dll" {
		t.Errorf("SharpGen DLL should remain pinned regardless of the dotnet override, got %q", sharpgen)
	}
}

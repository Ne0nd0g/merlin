# Contributing
Thank you for your interest in contributing to Merlin. This document
outlines some basic guidelines for submitting your contributions. This
 is a living document and it will be updated regularly as the project
 matures.

# Getting Started
Go is slightly unique due to the way it imports packages. Simply forking
 Merlin and getting to work will result in problems due to imports. The
 proper way to work with a Go repository after forking it is:
1. Grab Merlin into your GOPATH `go get github.com/Ne0nd0g/merlin`
2. Rename the current origin remote to upstream
`git remote rename origin upstream`
3. Add your fork as origin
`git remote add origin https://github.com/<your user name>/merlin`

An excellent blog post by
[Scott Mansfield](https://github.com/ScottMansfield) can be found
[here](https://blog.sgmansfield.com/2016/06/working-with-forks-in-go/).

# Logging
Commands executed against an agent should be logged in the agent log.
The results of messages executed on an agent, to include errors and
successes, should also be sent back to the server and logged in the
agent's log file. Command results can be sent back using the
"CmdResults" message structure.

Commands only affecting the server should be entered into the server's
log file.

When adding a new feature, ensure the associated activities are also
logged.

# User Interface Messages

* Informational messages are white and start with "[i]"
* Warning and Error messages are red and start with "[!]"
* Verbose messages (those that are not a warning or error) are yellow
and start with "[-]"
* Success messages are green and start with "[+]"
Informational messages are white and start with "[i]"
Debug messages are red and start with (in all caps) "[DEBUG]". These
messages go abover verbose logging and are used to track down problems
or print out raw data.
* Messages should be left alligned and rest against the message type
symbol

# Agent Messages
Merlin Agents are designed to run on a compromised host during a
penetration test. As such, the agent should never display any messages
to user on standard out or standard error *unless* verbose messages are
enable.

# Agent Availability
Agent availability is one of the top priorities. Error handling should 
NOT cause an agent to exit but instead it SHOULD fail open and continue
to operate. Display error messages only if VERBOSE messages are enabled.

# Pull Requests
* Pull requests (PR) should be submitted to the `dev` branch
* Be sure to pull down any changes from `dev` prior to creating a PR
* All pull request will require a review and approval prior to being
accepted and merged into `dev`
* Ensure all code is free from spelling and grammatical errors
* Ensure code passes `golint`
* Ensure code compiles without errors
* Ensure all errors are handled
* Error checking should be done as soon as possible
* Update the usage() function if applicable
* Ensure log entries are created in the respective log files
* Update docs/CHANGELOG.MD

# Contributors
Thank you to everyone that has contributed to Merlin. Your contributions
 help keep Merlin great and valuable.

* [@ahhh](https://github.com/ahhh)
* [@twigatech](https://github.com/twigatech)


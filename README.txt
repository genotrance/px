Px is a HTTP(s) proxy server that allows applications to authenticate through an NTLM proxy
server, typically used in corporate deployments, without having to deal with the actual NTLM
handshake. It is primarily designed to run on Windows systems and authenticates on behalf
of the application using the currently logged in Windows user account.

Px is very similar to "NTLM Authorization Proxy Server" (http://ntlmaps.sourceforge.net/)
and Cntlm (http://cntlm.sourceforge.net/) in that it sits between the corporate proxy and
applications and offloads the NTLM authentication. The primary difference in Px is to use
the currently logged in user's credentials to log in automatically rather than requiring the
user to provide the username, password (hash) and domain information. This is
accomplished by using Microsoft SSPI to generate the tokens and signatures required to
authenticate with the NTLM proxy.

NTLMAps and Cntlm were designed for non-Windows users stuck behind a corporate proxy.
As a result, they require the user to provide the correct credentials to authenticate. On
Windows, the user has already logged in with his credentials so Px is designed for Windows
users who would like to use tools that aren't designed to deal with NTLM authentication,
without having to supply and maintain the credentials within Px.

The following link from Microsoft provides a good starting point to understand how NTLM
authentication works:

	https://msdn.microsoft.com/en-us/library/dd925287.aspx

Configuration

Px requires only one piece of information in order to function - the server name and port of
the NTLM proxy server. This needs to be configured in px.ini. Without this, Px will not work
and exit immediately.

The noproxy capability allows Px to connect to hosts in the configured subnets directly,
bypassing the NTLM proxy altogether. This allows clients to connect to hosts within the
intranet without requiring additional configuration for each client or at the NTLM proxy.

There are a few other settings to tweak in the INI file but most are self-explanatory. A few
of the settings can be specified on the command line for convenience.

The binary distribution of Px runs in the background once started and can be quit by
running "px --quit". When run directly using Python, use CTRL-C to quit.

Examples

	Use proxyserver.com:80 and allow requests from localhost only
	px --proxy=proxyserver.com:80

	Don't use any forward proxy at all, just log what's going on
	px --proxy= --noproxy=0.0.0.0/0 --debug

	Allow requests from localhost and from your own ip address. This is very useful for Docker
	for Windows, because in a bridged docker network all requests from containers will originate
	from your hosts ip.
	px.exe --proxy=proxyserver.com:80 --gateway --allow=127.0.0.1,<your ip>

	Allow requests from everywhere. Be careful, every client will use your NTLM authentication.
	px.exe --proxy=proxyserver.com:80 --gateway

Remarks
In Docker for Windows you need to set your proxy to http://<your ip>:3128 (or whatever port your
px is listening to) and be aware of https://github.com/docker/for-win/issues/1380.

Workaround:
docker build --build-arg http_proxy=http://<your ip>:3128 --build-arg https_proxy=http://<your ip>:3128 -t containername ../dir/with/Dockerfile

Dependencies

Px doesn't have any GUI and runs completely in the background. It is distributed using
Python 3.x and PyInstaller to have a self-contained executable but can also be run using a
Python distribution with the following additional packages.

	netaddr, psutil, pywin32 OR winkerberos
	futures on Python 2.x

	NOTE: winkerberos is required on Python 3.6+ since pywin32 SSPI is broken.
		  https://github.com/genotrance/px/issues/9

In order to make Px a capable proxy server, it is designed to run in multiple processes. The
number of parallel workers or processes is configurable via px.ini. However, this only works
on Python 3.3+ since that's when support was added to share sockets across processes in
Windows. On older versions of Python, Px will run multi-threaded but in a single process.

Feedback

Px is definitely a work in progress and any feedback or suggestions are welcome. It is hosted
on GitHub (https://github.com/genotrance/px) with an MIT license so issues, forks and PRs are
most appreciated.

Credits

Px is based on code from all over the internet and especially acknowledges these sources:-

http://stackoverflow.com/questions/2969481/ntlm-authentication-in-python
http://www.oki-osk.jp/esc/python/proxy/
http://stupidpythonideas.blogspot.com/2014/09/sockets-and-multiprocessing.html
https://curl.haxx.se/mail/lib-2014-09/0070.html
https://github.com/fl4re/curl/blob/master/lib/curl_sasl_sspi.c
https://github.com/mongodb-labs/winkerberos/issues/19
https://www.tillett.info/2013/05/13/how-to-create-a-windows-program-that-works-as-both-as-a-gui-and-console-application/
http://www.boku.ru/2016/02/28/posting-to-console-from-gui-app/

Thank you to the following contributors as well for their PRs:-

https://github.com/ccbur

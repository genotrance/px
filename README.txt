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

Configuration

Px requires only one piece of information in order to function - the server name and port of
the NTLM proxy server. This needs to be configured in px.ini. Without this, Px will not work
and exit immediately.

The noproxy capability allows Px to connect to hosts in the configured subnets directly, 
bypassing the NTLM proxy altogether. This allows clients to connect to hosts within the 
intranet without requiring additional configuration for each client or at the NTLM proxy.

There are a few other settings to tweak in the INI file but most are self-explanatory. A few
of the settings can be specified on the command line for convenience.

	px --proxy=proxyserver.com:80 --noproxy=0.0.0.0/0 --debug

The binary distribution of Px runs in the background once started and can be quit by 
running "px --quit". When run directly using Python, use CTRL-C to quit.

Dependencies

Px doesn't have any GUI and runs completely in the background. It is distributed using 
Python 3.x and PyInstaller to have a self-contained executable but can also be run using a 
Python distribution with the following additional packages.

	netaddr, psutil, pywin32
	futures on Python 2.x

In order to make Px a capable proxy server, it is designed to run in multiple processes. The 
number of parallel workers or processes is configurable via px.ini. However, this only works
on Python 3.3+ since that's when support was added to share sockets across processes in
Windows. On older versions of Python, Px will run multi-threaded but in a single process.

Feedback

Px is definitely a work in progress and any feedback or suggestions are welcome. It is hosted
on GitHub (https://github.com/genotrance/px) with an MIT license so issues, forks and pushes
are most appreciated.

Credits

Px is based on code from all over the internet and especially acknowledges these sources:-

http://stackoverflow.com/questions/2969481/ntlm-authentication-in-python
http://www.oki-osk.jp/esc/python/proxy/
http://stupidpythonideas.blogspot.com/2014/09/sockets-and-multiprocessing.html
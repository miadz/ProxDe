ProxDe
======

A proxy detection tool without an IP range filter

IMPORTANT:
------
Before I get into the other stuff, there's something important that has to be said about this tool.
<br>
This only detects SOME proxies (because many don't have the required headers exposed) so consider this as a layer of protection. At the moment, it's impossible to detect all proxies.

Current version
------
v1.1

Features:
------
&bull; Cloudflare support - ALPHA (Look at the notes in the script in regards to this.)
<br>
&bull; An array of proxy headers to detect (see what I did there?)
<br>
&bull; Easy to use
<br>
&bull; Ability to modify to your likings or needs
<br>
&bull; Use it in your projects and / or site(s)!

Usage:
------
<b>real_ip(1)</b> - Returns boolean 'true' if the header results provided match. If there's no match, returns 'false'.
<b>real_ip(2)</b> - Outputs potentially real IP address.

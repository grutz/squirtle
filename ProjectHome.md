# Welcome to Squirtle #

The purpose of this little doodad is to help you prove to your employer, your client, your best friend, your dog, or God that NTLM is truly dead. It does this by taking control of any browser that comes into contact with it and making it perform NTLM authentication at will. By using a set of API calls you can embed Squirtle into existing penetration toolkits, proxies or other fun tools at your disposal.

The latest version of Squirtle should always be obtained with your SVN client of choice:

`svn checkout http://squirtle.googlecode.com/svn/trunk/ squirtle-read-only`

## Squirtle Attack Scenarios ##

**XSS == Domination**

Thanks to Internet Explorer's automatic security zones, servers on the 'inside' are typically within the "Trusted Zone" by default. This means IE will negotiate and send NTLM credentials at the drop of a hat. With one cross site scripting vulnerability or even basic social engineering it's possible to now grab these hashes with a static nonce like crazy. Sure it's been done via SMB but this is HTTP!

More background here: http://grutz.jingojango.net/exploits/pokehashball.html -- Squirtle performs this attack by default when a user connects to it.

**Pass The Dutchie**

You've heard of "Pass The Hash" and SMBRelay attacks where the attacker uses the LM/NT hashes to connect to SMB shares, right? Here's a new attack I'm calling "Pass The Dutchie".

Past attack methods have been focused on single-threaded attacks, either against a single server/resource or back to the client connecting. With Squirtle a client browser is held and asked to perform NTLM authentication at any time opening attacked resources to be any number of web servers, SMB shares, SQL Servers, etc.

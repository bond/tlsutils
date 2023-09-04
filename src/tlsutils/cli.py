import argparse
import sys
import ssl
from datetime import datetime

from . import helper
from . import tlssocket

from yaml import dump

def tlsinfo():
    """
    CLI-command "tlsinfo" to print information about a tls-server certificate.
    """
    parser = argparse.ArgumentParser(description='Generate CSRs')
    parser.add_argument('hostname', type=str, help='Hostname to connect to')
    parser.add_argument('-p','--port', metavar='PORT', type=int, default=443, help="The port to connect to.")
    parser.add_argument('-k', '--insecure', dest='insecure', action='store_true', help='Allow invalid certificates')
    parser.add_argument('-v', dest='verbose', action='store_true', help="Add more verbose output.")
    args = parser.parse_args()
    
    # default_context also loads system CA-store/certificates.
    context = ssl.create_default_context()

    # default is to require valid cert
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL
        
        
    try:
        tlsinfo = tlssocket.get_tlsinfo(context, args)
        srvcert = tlsinfo.cert
    except ssl.SSLCertVerificationError as e:
        print(f"SSL Connection error, invalid certificate: {e}")
        sys.exit(1)


    valid_hostname = False
    try:
        ssl.match_hostname(srvcert, args.hostname)
        valid_hostname = True
    except ssl.SSLCertVerificationError:
        pass

    # expiry date
    now = datetime.now()
    expires = datetime.utcfromtimestamp(ssl.cert_time_to_seconds(srvcert.get('notAfter')))
    date_delta = expires - now

    # non-verbose does a short version
    if not args.verbose:
        if valid_hostname:
            print(f'Ok, expires in {date_delta}')
            sys.exit(0)
        else:
            print(f'Invalid certificate, expires in {date_delta}')
            sys.exit(1)


    subject = helper.flatten_tuple(srvcert.get('subject'))
    altNames = helper.flatten_tuple(srvcert.get('subjectAltName'))

    issuer = dict(helper.flatten_tuple(srvcert.get('issuer')))

    data = {
        'issuer': {
            'organizationName': issuer.get('organizationName'),
            'commonName': issuer.get('commonName'),
        },
        'certificate': {
            'valid_from': srvcert.get('notBefore'),
            'valid_to': srvcert.get('notAfter'),
            'expires_in': str(date_delta),
            # make a list of key-value pairs
            'subject': list(map(lambda x: {x[0]: x[1]}, subject)),
            'alt_names': list(map(lambda x: ':'.join(x), altNames)),
        }
    }

    # verbose information
    if args.verbose:
        data['certificate']['serial'] = srvcert.get('serialNumber')
        data['tls_version'] = tlsinfo.tls_version

        # add the verbose 

    # print YAML output
    print(dump(data))


if __name__ == '__main__':
    """
    When file is invoked manually, call tlsinfo()
    """
    sys.exit(tlsinfo())
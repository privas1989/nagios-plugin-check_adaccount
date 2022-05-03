#!/usr/bin/env python3
import sys, ldap, datetime, argparse, os

# Custom definitions
def usage():
    print('Example: python check_ad_pass_expr.py -u user.test -w 30 -r 200 -d example.com -b OU=users,DC=example,DC=com')

def ad_timestamp(timestamp):
    if timestamp != 0:
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=timestamp/10000000)
    return np.nan
    
# Variables
attrs = ['pwdLastSet','samaccountname']
dt_now = datetime.datetime.now()
ca_cert_file = ''
parser = argparse.ArgumentParser()
parser.add_argument("-u", help="SamAccountName of the AD user.")
parser.add_argument("-w", help="Amount of days before password expiration that triggers a warning.")
parser.add_argument("-r", help="Amount of days before a password needs to be reset.")
parser.add_argument("-d", help="The target LDAP domain.")
parser.add_argument("-base", help="The LDAP search base.")
parser.add_argument("-buser", help="The LDAP bind user.")
parser.add_argument("-bpassword", help="The LDAP bind password.")
args = parser.parse_args()

if args.u and args.w and args.r:

    days_warning = -1 * int(args.w)
    days_pwd_expire = int(args.r)
    search_filter = '(&(objectClass=user)(samaccountname=' + args.u + '))'
    server_uri = 'ldaps://'+ args.d + ':636'
    search_base = args.base
    bind_u = args.buser
    bind_p = args.bpassword

    # Connect to LDAP
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    connection = ldap.initialize(server_uri)
    connection.protocol_version = ldap.VERSION3
    connection.set_option(ldap.OPT_REFERRALS, 0)
    connection.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
    connection.set_option(ldap.OPT_X_TLS_CACERTFILE, ca_cert_file)
    connection.set_option(ldap.OPT_X_TLS_DEMAND, True )
    #connection.set_option(ldap.OPT_DEBUG_LEVEL, 255)

    connection.simple_bind_s(bind_u, bind_p)
    results = connection.search_s(
        search_base,
        ldap.SCOPE_SUBTREE,
        search_filter,
        attrs
    )   

    connection.unbind()

    pwdLastSet = int(results[0][1]['pwdLastSet'][0].decode('utf-8'))
    pwdLastSetDT = ad_timestamp(pwdLastSet)
    expire_date = pwdLastSetDT + datetime.timedelta(days=days_pwd_expire)
    if expire_date < dt_now:
        print('PWD CRITICAL - The password has expired. Please reset the password ASAP!')
        sys.exit(2)
    elif (dt_now >= expire_date + datetime.timedelta(days=days_warning)) and (dt_now < expire_date): 
        print('PWD WARNING - The password is about to expire. Please reset the password ASAP.')
        sys.exit(1)
    elif expire_date >= dt_now:
        print('PWD OK - The password is within the password expiration guidelines.')
        sys.exit(0)
    else:
        print('UNKNOWN')
        sys.exit(3)
else:
    usage()
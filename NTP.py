#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import cloudgenix_settings
import sys
import logging
import os
import datetime
from csv import DictReader
import time


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example NTP script'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

def update(cgx, ntp_name_check, domain):
    ntp_id = None
    ntp_hosts = None
    ntp_name = None
    ntp_tags = None
    for ntp in cgx.get.templates_ntp().cgx_content['items']:
        if ntp["name"] == ntp_name_check:
            ntp_id = ntp["id"]
            ntp_hosts = ntp["ntp_servers"]
            ntp_name = ntp["name"]
            ntp_tags = ntp["tags"]
    if not ntp_id:
        print("No NTP name " + str(ntp_name) + " found")
        return
    
    domain_id = None
    if domain:
        for binding in cgx.get.servicebindingmaps().cgx_content['items']:
            if binding["name"] == domain:
                domain_id = binding["id"]
    if not domain_id:
        print("No domain found so will update all sites in 20 seconds")
        num = 20
        while num != 0:
            print("Starting in " + str(num))
            num -= 1
        
                    
    for site in cgx.get.sites().cgx_content['items']:
        if site["element_cluster_role"] == "SPOKE":
            if domain_id:
                if domain_id == site["service_binding"]:
                    for element in cgx.get.elements().cgx_content['items']:
                        sid = element['site_id']
                        model_name = element['model_name']
                        if element['site_id'] == site["id"]:
                            for ntp in cgx.get.ntp(element_id=element["id"]).cgx_content['items']:
                                update = False
                
                                if ntp["name"] != ntp_name:
                                    print("Updating due to wrong name")
                                    update = True
                                elif ntp["ntp_servers"] != ntp_hosts:
                                    print("Update due to wrong ntp servers")
                                    update = True
                                elif ntp["tags"] != ntp_tags:
                                    print("Update due to wrong ntp tags")
                                    update = True
                
                                if update:
                                    ntp["name"] = ntp_name
                                    ntp["ntp_servers"] = ntp_hosts
                                    ntp["tags"] = ntp_tags
                                    resp = cgx.put.ntp(element_id=element["id"], ntp_id=ntp["id"], data=ntp)                 
                                    if not resp:
                                        print("Error updating NTP " + ntp_name_check +" on " + element["name"] + " site " + site["name"])
                                        print(str(jdout(resp)))
                                    print("Updating NTP " + ntp_name_check +" on " + element["name"] + " site " + site["name"])
                                else:
                                    print("No updated required for NTP " + ntp_name_check +" on " + element["name"] + " site " + site["name"])
            else:
                for element in cgx.get.elements().cgx_content['items']:
                    sid = element['site_id']
                    model_name = element['model_name']
                    if element['site_id'] == site["id"]:
                        for ntp in cgx.get.ntp(element_id=element["id"]).cgx_content['items']:
                            update = False
                
                            if ntp["name"] != ntp_name:
                                print("Updating due to wrong name")
                                update = True
                            elif ntp["ntp_servers"] != ntp_hosts:
                                print("Update due to wrong ntp servers")
                                update = True
                            elif ntp["tags"] != ntp_tags:
                                print("Update due to wrong ntp tags")
                                update = True
                
                            if update:
                                ntp["name"] = ntp_name
                                ntp["ntp_servers"] = ntp_hosts
                                ntp["tags"] = ntp_tags
                                resp = cgx.put.ntp(element_id=element["id"], ntp_id=ntp["id"], data=ntp)                 
                                if not resp:
                                    print("Error updating NTP " + ntp_name_check +" on " + element["name"] + " site " + site["name"])
                                    print(str(jdout(resp)))
                                print("Updating NTP " + ntp_name_check +" on " + element["name"] + " site " + site["name"])
                            else:
                                print("No updated required for NTP " + ntp_name_check +" on " + element["name"] + " site " + site["name"])
                    
    return
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    config_group = parser.add_argument_group('Name', 'These options change how the configuration is loaded.')
    config_group.add_argument("--name", "-N", help="NTP Template", required=True, default=None)
    config_group.add_argument("--domain", "-DN", help="NTP Template", required=False, default=None)
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
                             
    args = vars(parser.parse_args())
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    ntp_name_check = args["name"]
    domain = args["domain"]

    
    update(cgx, ntp_name_check, domain) 
    # end of script, run logout to clear session.
    print("End of script. Logout!")
    cgx_session.get.logout()

if __name__ == "__main__":
    go()
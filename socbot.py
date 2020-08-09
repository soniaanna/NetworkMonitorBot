from webexteamssdk import WebexTeamsAPI
import requests
from datetime import datetime
import pytz
import creds

class Bot:
    def __init__(self):
        self.token = f'{creds.token}'
        self.room_id = f'{creds.roomId}'
        self.api = WebexTeamsAPI(access_token=self.token)

    def message(self, message):
        self.api.messages.create(roomId=self.room_id, text=message)


def allopenattacks():
    url = "creds.url_attack"
    r = requests.get(url)
    response = r.text
    return response


def checkip(ip):
    url = f"creds.url_ip"
    r = requests.get(url)
    response = r.text
    return response


# =================BGP PATHS=================
# This data call returns information commonly coming from a Looking Glass. The data is based on a data feed from
# the RIPE NCC's network of BGP route collectors (RIS, see https://www.ripe.net/data-tools/stats/ris for more
# information).
# The data processing usually happens with a small delay and can be considered near real-time.
# The output is structured by collector node (RRC) accompanied by the location and the BGP peers which provide
# the routing information.

# https://stat.ripe.net/data/looking-glass/data.json?resource=x

def get_bgp_paths(ip):
    query = f"https://stat.ripe.net/data/looking-glass/data.json?resource={ip}"
    r = requests.get(query)
    response_dict = r.json()

    return response_dict


def filter_bgp_paths(dict):
    data = dict['data']
    rrcs_list = data['rrcs']
    as_paths = {}
    for location in rrcs_list:
        as_paths.update({location["peers"][0]['peer']: location["peers"][0]['as_path']})
    return as_paths


# checkleaks <IP address or CIDR> - Reply with a list of AS paths that did not include my ASN in the path
def checkleaks(ip):
    all_as_paths = filter_bgp_paths(get_bgp_paths(ip))

    # Filter the dictionary of paths.
    leaking_as_paths = {}
    for key, value in all_as_paths.items():
        if f'{creds.ASN}' not in value:
            leaking_as_paths.update({key, value})

    if len(leaking_as_paths) == 0:
        response_string = f'No leaks for: {ip}'
    else:
        response_string = f'BGP paths with leaks for the IP {ip}:\n\n'
        for key, value in leaking_as_paths.items():
            response_string = response_string + 'Peer: ' + key + '\tAS path: ' + value + '\n'

    return response_string


# checkonplatform <IP address or CIDR> - Reply with a list of AS paths that included our ASN
#  in the path
def checkonplatform(ip):
    all_as_paths = filter_bgp_paths(get_bgp_paths(ip))

    as_paths_onplatform = {}

    for key, value in all_as_paths.items():
        if f'{creds.ASN}' in value:
            as_paths_onplatform.update({key: value})

    if len(as_paths_onplatform) == 0:
        response_string = f'The IP {ip} is not routed through platform.'
    else:
        response_string = f'BGP paths that include platform ASN for the IP {ip}:\n\n'
        for key, value in as_paths_onplatform.items():
            response_string = response_string + 'Peer: ' + key + '\tAS path: ' + value + '\n'
    return response_string


#lgleaks <IP address or CIDR> - Reply with a list of AS paths that do not include our ASN in the
#  path.
def lgleaks(ip):
    all_as_paths = filter_bgp_paths(get_bgp_paths(ip))

    # Filter the dictionary of paths.
    leaking_as_paths = {}
    for key, value in all_as_paths.items():
        if f'{creds.ASN}' not in value:
            leaking_as_paths.update({key, value})

    if len(leaking_as_paths) == 0:
        response_string = f'No leaks for the IP: {ip}'
    else:
        response_string = f'There are multiple leaks for the IP {ip}:\n\n'
    return response_string


#lgroute <IP address or CIDR> - Reply with answer to whether the IP address or CIDR is routed on the
#  network and, if it is, whether route leaks exist from the perspective of the RIPEstat server.
def lgroute(ip):
    all_as_paths = filter_bgp_paths(get_bgp_paths(ip))

    as_paths_onplatform = {}

    for key, value in all_as_paths.items():
        if creds.ASN in value:
            as_paths_onplatform.update({key: value})

    if len(as_paths_onplatform) == 0:
        response_string = f'The IP {ip} is not routed through platform.'
    else:
        response_string = f'The IP {ip} is routed through platform. Check if there are any leaks by using the command ' \
            f'"checkleaks <ip>"'

    return response_string

# =================PEAKS=================
# TODO ippeaks <a.b.c.d> - Reply with peak BPS and PPS information for the IP address provided.

# =================ATTACKS=================
# TODO attackupdate <ccname> - Reply with attack update template containing information from all currently open
#  attack events.
#


def attackupdate(ccname):
    #TODO
    # Fetch attacks ( api sallopen)
    # FIlter by cname and find attack id
    # Fetch xiphos data for the attack
    # Get info: events, ips, vectors, peaks bps, pps

    attack_event_id_list = []
    ip_list = []
    vector_list = []
    peaks_bps = []
    peaks_pps = []
    response = "- Customer: " + ccname
    response = response + "\n- Service: "
    response = response + "\n- Attack Event ID(s): " + str(attack_event_id_list)
    response = response + "\n- Attack Traffic Status: ACTIVE/INACTIVE"
    response = response + "\n- Update Interval: 4 Hours"
    response = response + "\n- Target IP(s): " + str(ip_list)
    utc = pytz.timezone('Europe/London')
    response = response + "\n- Reviewed Date / Time: " + str(datetime.now(utc)) + " UTC"
    response = response + "\n- Attack Vector(s): " + str(vector_list)
    response = response + "\n- Max Aggregated Volume (Bandwidth): " + str(peaks_bps)
    response = response + "\n- Max Aggregated Volume (PPS): " + str(peaks_pps)
    return response


def help():
    help_msg = 'Hi. Check out the commands.\n' \
               '- allopenattacks\n' \
               '- checkip <ip>\n' \
               '- checkleaks <ip>\n' \
               '- checkonplatfrom <ip\n' \
               '- attackupdate <cname>\n' \
               '- attackpeaks <ip>\n' \
               '- lgleaks <ip>\n' \
               '- lgroute <ip>\n' \
               'socbot junior'
    return help_msg




if __name__ == '__main__':
    bot = Bot()
    #bot.message(help())
    #bot.message('checkleaks <ip>\ncheckleaks \n')
    #bot.message(checkonplatform(''))
    #
    # bot.message('checkonplatform <ip>\ncheckonplatform \n')
    # bot.message(checkonplatform(''))
    # print(bot.checkleaks(''))
    # print(bot.checkonplatform(''))

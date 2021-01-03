#!/usr/bin/env python3
#
# (C) 2020 by Harald Welte <laforge@osmocom.org>
#
# SPDX-License-Identifier: MIT
#
# This is a simplistic program to show how the REST API of osmo-cbc can be used to
# create and delete Cell Broadcast Messages
#
# A lot of the parameters are currently hard-coded, see the 'js' variable definitions
# below.

import sys
import argparse
import requests


def build_url(suffix):
    BASE_PATH= "/api/ecbe/v1"
    return "http://%s:%u%s%s" % (server_host, server_port, BASE_PATH, suffix)


def rest_post(suffix, js = None):
    url = build_url(suffix)
    if verbose:
        print("POST %s (%s)" % (url, str(js)))
    resp = requests.post(url, json=js)
    if not resp.ok:
        print("POST failed")

def rest_delete(suffix, js = None):
    url = build_url(suffix)
    if verbose:
        print("DELETE %s (%s)" % (url, str(js)))
    resp = requests.delete(url, json=js)
    if not resp.ok:
        print("DELETE failed " + str(resp))



def main(argv):
    global server_port, server_host, verbose

    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to connect to", default="localhost")
    parser.add_argument("-p", "--port", help="TCP port to connect to", default=12345)
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action='count', default=0)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--create-cbs", type=int, nargs=1, metavar=('msg_id'))
    group.add_argument("-e", "--create-etws", type=int, nargs=1, metavar=('msg_id'))
    group.add_argument("-d", "--delete", type=int, nargs=1, metavar=('msg_id'))

    args = parser.parse_args()

    server_host = args.host
    server_port = args.port
    verbose = args.verbose

    if args.create_cbs:
        js = {
            'cbe_name': "cbc_apitool",
            'category': "normal",
            'repetition_period': 5,
            'num_of_bcast': 888,
            'scope': {
                'scope_plmn': { }
            },
            'smscb_message': {
                'message_id': int(args.create_cbs[0]),
                'serial_nr': {
                    'serial_nr_decoded': {
                        'geo_scope': "plmn_wide",
                        'msg_code': 768,
                        'update_nr': 0
                    }
                },
                'payload': {
                    'payload_decoded': {
                        'character_set': "gsm",
                        #'language': 'en',
                        #'data_utf8': "Mahlzeit!"
                        'data_utf8': "Mahlzeit1 Mahlzeit2 Mahlzeit3 Mahlzeit4 Mahlzeit5 Mahlzeit6 Mahlzeit7 Mahlzeit8"
                        #'data_utf8': "Mahlzeit1 Mahlzeit2 Mahlzeit3 Mahlzeit4 Mahlzeit5 Mahlzeit6 Mahlzeit7 Mahlzeit8 Mahlzeit9 Mahlzeit10 Mahlzeti11 Mahlzeit12 Mahlzeit13 Mahlzeit14 Mahlzeit15 Mahlzeit16 Mahlzeit17 Mahlzeit18 Mahlzeit19 Mahlzeit20 Mahlzeit21 Mahlzeit22 Mahlzeit23 Mahlzeit24 Mahlzeit25 Mahlzeit26 Mahlzeit27 Mahlzeit28"
                    }
                }
            }
        }
        rest_post("/message", js);

    elif args.create_etws:
        js = {
            'cbe_name': "cbc_apitool",
            'category': "normal",
            'repetition_period': 5,
            'num_of_bcast': 999,
            'scope': {
                'scope_plmn': { }
            },
            'smscb_message': {
                'message_id': int(args.create_etws[0]),
                'serial_nr': {
                    'serial_nr_decoded': {
                        'geo_scope': "plmn_wide",
                        'msg_code': 768,
                        'update_nr': 0
                    }
                },
                'payload': {
                    'payload_etws': {
                        'warning_type': {
                            'warning_type_decoded': 'earthquake'
                        },
                        'emergency_user_alert': True,
                        'popup_on_display': True
                    }
                }
            }
        }
        rest_post("/message", js);

    elif args.delete:
        rest_delete("/message/%u" % (args.delete[0]))
    else:
        print("No operation?!");


if __name__ == "__main__":
    main(sys.argv)

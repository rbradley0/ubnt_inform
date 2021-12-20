# coding: utf-8
'''
Unifi Inform Protocol plugin for Puffin WebServer, all code is from documentation about how the Unifi Inform Protocol works and functions.

This script is an updated working rewrite of the script published by Eric W <Brontide@GitHub> that uses Snappy, Zlib, pycryptodome, and Flask.
Snappy and pycryptodome are the only real deviations from the original because pysnappy fails to compile on my system and pycryto doesn't seem to
support AES-GCM mode.

Authors: Ryan Bradley <rbradley0@foxsys.org>

Credit: Eric W <Brontide@GitHub>, Felix Kaiser <fxkr@GitHub>, Jeffery Kog <jefferykog@GitHub>

'''

from flask import Blueprint, request
from .inform import *

__plugin__ = "ubnt_inform"
__version__ = "0.0.1"

ubnt_inform = Blueprint("ubnt_inform", __name__, template_folder='templates')

@ubnt_inform.route("/")
def index():
    return "Hello :D"

@ubnt_inform.route("/inform", methods=['POST'])
def inform():
    data = request.get_data()
    inform = Packet(from_packet=data)
    print(inform)

class InformServer(WebPlugin):
    def setup(self):
        self.register_blueprint(ubnt_inform, url_prefix='/')

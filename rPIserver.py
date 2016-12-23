#!/usr/bin/python
# -*- coding: utf-8 -*-
#

# Trying SSL with bottle
# ie combo of http://www.piware.de/2011/01/creating-an-https-server-in-python/
# and http://dgtool.blogspot.com/2011/12/ssl-encryption-in-python-bottle.html
# without cherrypy?
# requires ssl

# to create a server certificate, run eg
# openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
# or openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
# DON'T distribute this combined private/public key to clients!
# (see http://www.piware.de/2011/01/creating-an-https-server-in-python/#comment-11380)
import ConfigParser
import csv
import hashlib
import json
import logging
import subprocess
import sys
import os
from logging.handlers import RotatingFileHandler
from bottle import get, post, run, ServerAdapter, route, error, template, server_names, install
from bottle import request, response, HTTPError, redirect, auth_basic
import tdtool
from kodipydent import Kodi
from time import sleep
from functools import wraps
from datetime import datetime
from fabric.api import env, settings
from fabric.api import run as frun
from fabric.api import local as flocal
import socket

project = 'rPIserver'
INI_file = project + '.cfg'

port = None
config = None
user_name = None
password = None
cookie_key = 'abH15cGdExsz=='
host = "0.0.0.0"
url = None

rPIs = {
    'rPI_DAC': '192.168.0.20',
    'rPI_SPDIF': '192.168.0.13',
    'rpiMON': '192.168.0.12',
    'NAS': '192.168.0.16',
    'rPI1': '192.168.0.11'
}
devices = {
    'rPI_DAC': 199137,
    'rPI_SPDIF': 274164,
    'A3': 274166,
    'SAM': 223659,
    'NAS': 274165
}
methods = {
    'ON': tdtool.TELLSTICK_TURNON,
    'OFF': tdtool.TELLSTICK_TURNOFF,
    'DIM': tdtool.TELLSTICK_DIM
}


def openlog(file):
    # Setup the log handlers to stdout and file.
    log = logging.getLogger(project)
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
    )
    handler_stdout = logging.StreamHandler(sys.stdout)
    handler_stdout.setLevel(logging.DEBUG)
    handler_stdout.setFormatter(formatter)
    log.addHandler(handler_stdout)

    handler_file = RotatingFileHandler(
        file,
        mode='a',
        maxBytes=1048576,
        backupCount=9,
        encoding='UTF-8',
        delay=True
    )
    handler_file.setLevel(logging.DEBUG)
    handler_file.setFormatter(formatter)
    log.addHandler(handler_file)
    return log


log = openlog(project + '.log')


def log_to_logger(fn):
    """
    Wrap a Bottle request so that a log line is emitted after it's handled.
    (This decorator can be extended to take the desired logger as a param.)
    """

    @wraps(fn)
    def _log_to_logger(*args, **kwargs):
        request_time = datetime.now()
        actual_response = fn(*args, **kwargs)
        # modify this to log exactly what you need:
        if request.method == 'POST':
            sep = '?'
        else:
            sep = ''

        log.info('%s %s %s %s %s' % (request.remote_addr,
                                     request_time,
                                     request.method,
                                     request.url + sep + request.body.buf,
                                     response.status))
        return actual_response

    return _log_to_logger


# check header username and password
def protected(check, realm="private", text="Access denied", api=False):
    def decorator(func):
        def wrapper(*a, **ka):
            global url
            url = str(request.url).replace('http', 'https')
            # check first if a cookie exists
            user = request.get_cookie('account', secret=cookie_key)
            if user is None:
                # check then if the header contains authentication variables
                user, password = request.auth or (None, None)
                authenticated = check(user, password)
            else:
                authenticated = True
            if not authenticated and api == True:
                response.headers['WWW-Authenticate'] = 'Basic realm="%s"' % realm
                return HTTPError(401, text)
            elif not authenticated:
                redirect("https://home.mayeur.be:%s/login" % port)
            url = None
            return func(*a, **ka)

        return wrapper

    return decorator


# copied from bottle. Only changes are to import ssl and wrap the socket
class SSLWSGIRefServer(ServerAdapter):
    def run(self, handler):
        """
        Runs a CherryPy Server using the SSL certificate.
        """
        from cherrypy import wsgiserver
        from cherrypy.wsgiserver.ssl_pyopenssl import pyOpenSSLAdapter

        server = wsgiserver.CherryPyWSGIServer((self.host, self.port), handler)
        self.server = server
        server.ssl_adapter = pyOpenSSLAdapter(
            certificate=certfile,
            private_key=keyfile,
            # certificate_chain = cert_chain
        )
        server.start()
        # try:
        #     server.start()
        # except:
        #     server.stop()

    def stop(self):
        try:
            # self.srv.shutdown()
            log.info('Stopping server')
            self.server.stop()
        except:
            pass


def check_login(usr, pwd):
    # Return True if username and password are valid.
    if usr != user_name:
        return False

    pwd = hashlib.sha224(pwd).hexdigest()
    if pwd != password:
        return False
    else:
        return True


@route('/whoami')
@auth_basic(check_login)
def who():
    return 'rPIserver'


@route('/api')
@protected(check_login, api=True)
def display_action():
    action = request.query.cmd
    method = request.query.param

    try:
        if (action == 'spam'):
            if os.name == 'nt':
                env.host_string = 'rpiMON'
                env.user = 'pi'
                env.use_ssh_config = True

            if method == "":
                method = "status"

            with settings(warn_only=True):
                if os.name == 'nt':
                    out = method + " - " + frun('sudo service SpamMon %s' % method)
                elif os.name == 'posix':
                    out = method + " - " + flocal('sudo service SpamMon %s' % method, capture=True)

            response.content_type = 'text/plain'
            #
            # fields = ('Date', 'Process', 'Severity', 'Description')
            # with open(logfile, 'rb') as f:
            #     reader = csv.DictReader(f, fieldnames=fields, delimiter='|')
            #     out = json.dumps([row for row in reader], indent=4)
            # response.content_type = 'application/json'
            #
            return out

        elif method == "":
            p = subprocess.Popen([action], stdout=subprocess.PIPE)
        else:
            p = subprocess.Popen([action, method], stdout=subprocess.PIPE)

        response.content_type = 'text/plain'
        out = ''
        for line in p.stdout:
            out += line.strip() + '\r\n'
        return out  # template('{{out}}', out=out)

    except Exception, e:
        return template('Error: %s' % e)


@error(404)
def error404(error):
    return 'Error 404'


@get('/login')  # or @route('/login')
def login():
    return '''
        <form action="/login" method="post">
            Username: <input name="username" type="text" /> <br/>
            Password: <input name="password" type="password" />
            <input value="Login" type="submit" />
        </form>
    '''


@get('/logout')
def logout():
    response.set_cookie('account', None, secret=cookie_key)
    return "<p>Your are now logged out.</p>"


@post('/login')  # or @route('/login', method='POST')
def do_login():
    username = request.forms.get('username')
    pwd = request.forms.get('password')
    if check_login(username, pwd):
        response.set_cookie('account', username, secret=cookie_key, max_age=3000)
        if url is None:
            return "<p>Your login information was correct.</p>"
        else:
            redirect(url)
    else:
        return "<p>Login failed.</p>"


@post('/post')
@protected(check_login, api=True)
def do_post():
    try:
        data = request.body.read()
        print (data)
    except:
        print ('No data here')


@get('/tdlist')
@protected(check_login, api=True)
def do_tdlist():
    response.content_type = 'application/json'
    return tdtool.listDevices()


@post('/tdcmd')
@protected(check_login, api=True)
def do_tdcmd():
    """
    Post a command to the Telldus server
    syntax: https://home.mayeur.be:<port>/tdcmd?id=<nnn>&method=<x>[&value=<x>]

    :return:
    """

    resp = 'failed!'
    try:
        id = devices[request.forms.get('id')]
        method = methods[request.forms.get('method')]
    except:
        id = None
        method = None

    if id is not None and method is not None:
        if method == tdtool.TELLSTICK_DIM:
            try:
                value = request.forms.get('value')
            except:
                value = 100
            resp = tdtool.doMethod(id, method, value)
        else:
            resp = tdtool.doMethod(id, method)

    response.content_type = 'text/plain'
    return resp


@get('/tdstate')
@protected(check_login, api=True)
def do_tdstate():
    """
    # /kodistate?id=<device>
    :return: 'ON', 'OFF'
    """
    id = request.query.id
    response.content_type = 'text/plain'
    return  tdtool.getDeviceState(devices[id])


@get('/kodistate')
@protected(check_login, api=True)
def do_kodistate():
    """
    # /kodistate?id=<device>
    :return: 'ON', 'OFF'
    """
    id = request.query.id
    resp = tdtool.getDeviceState(devices[id])
    if resp == 'OFF':
        return 'OFF'
    else:
        try:
            kodi = Kodi(rPIs[id])
            resp = kodi.JSONRPC.Ping()
            return 'Kodi On'
        except:
            # resp = tdtool.doMethod(devices[id], methods['OFF'])
            return 'POWERED'


@post('/kodi')
@protected(check_login, api=True)
def do_kodi():
    """
    # /kodi?id=[rPI_DAC | rPI_SPDIF]&method=['ON'|'OFF']

    :return:
    """
    try:
        id = request.forms.get('id')
        method = request.forms.get('method')
        kodi_ip = rPIs[id]
    except:
        kodi_ip = None

    if method == 'ON':
        resp = tdtool.doMethod(devices[id], methods[method])

    count = 0
    if method == 'ON':
        maxcount = 10
    else:
        maxcount = 1
    while count < maxcount:
        try:
            kodi = Kodi(kodi_ip)
            print 'Connected to Kodi %s' % id
            break
        except:
            print 'Retrying...'
            sleep(1)
            count += 1
    else:
        # resp = tdtool.doMethod(devices[id], methods['OFF'])
        if method == 'ON':
            return 'POWERED'
        else:
            print 'Failed'
            return 'Failed'

    response.content_type = 'application/json'
    if method == 'ON':
        resp = kodi.JSONRPC.Version()
        return 'Kodi On'
    else:
        resp = kodi.System.Shutdown()
        sleep(5)
        resp = tdtool.doMethod(devices[id], methods[method])
        return 'OFF'


@post('/ping')
@protected(check_login, api=True)
def do_ping():
    """
    Post a command to probe a server connection
    syntax: https://home.mayeur.be:<port>/ping?id=<nnn>]
    :return:
    """
    dev = rPIs[request.forms.get('id')]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((dev, 22))
        return 'Alive'
    except socket.error:
        return 'Failed'

def send_to_pipe(p):
    while True:
        p.send('beep')
        sleep(2)


def get_from_pipe(p):
    while True:
        msg = p.recv()
        print msg
        if msg is None:
            print "Arrgh, a poison pill! - I'm dying!"
            sys.exit()


def open_config(f):
    # Read config file
    config_ = None
    for loc in os.curdir, os.path.expanduser('~').join('.' + project), os.path.expanduser('~'), \
               '/etc/' + project, os.environ.get(project + '_CONF'):
        try:
            with open(os.path.join(loc, f), 'r+') as config_file:
                config_ = ConfigParser.SafeConfigParser()
                config_.readfp(config_file)
                break
        except IOError:
            pass
    if config_ is None:
        log.critical('configuration file is missing')
    return config_


if __name__ == '__main__':
    # Open the config file
    # and read the key options
    config = open_config(INI_file)
    try:
        section = 'server'
        option = 'port'
        port = config.get(section, option)

        option = 'public_key'
        certfile = config.get(section, option)

        option = 'secret_key'
        keyfile = config.get(section, option)

        option = 'cert_chain'
        cert_chain = config.get(section, option)

        section = 'user'
        option = 'name'
        user_name = config.get(section, option)

        option = 'password'
        password = config.get(section, option)

    except ConfigParser.NoOptionError:
        log.critical('Missing option %s' % option)
        sys.exit(1)
    except ConfigParser.NoSectionError:
        log.critical('Missing section %s' % section)
        sys.exit(1)

    # p_in, p_out = Pipe()
    # stp = Process(target=send_to_pipe, args=(p_in,))
    # gfp = Process(target=get_from_pipe, args=(p_out,))
    # stp.start()
    # gfp.start()

    # Lauch a process to reply to UDP broadcast with IP address
    # send_myIP = Process(target=UDPlisten.send_IP, args=(8888,))
    # send_myIP.start()

    # p_in.send(None)


    tdtool.init('rPIserver.cfg')
    # Start the WSIG server
    log.info('Starting server listening on port %s' % port)
    server_names['SSLWSGIRefServer'] = SSLWSGIRefServer
    install(log_to_logger)
    run(host='0.0.0.0', port=port, server='SSLWSGIRefServer')


import argparse
import logging
import sys
import asyncio
from aiohttp import web
from zmq.asyncio import ZMQEventLoop

from sawtooth_sdk.processor.log import init_console_logging

from rest_api.router_handler import RouterHandler
from rest_api.messaging import Messenger

LOGGER = logging.getLogger(__name__)


def parse_args(args):
    parser = argparse.ArgumentParser(
        description='Starts the Simple Login REST API')

    parser.add_argument(
        '-B', '--bind',
        help='identify host and port for api to run on',
        default='localhost:8008')
    parser.add_argument(
        '-C', '--connect',
        help='specify URL to connect to a running validator',
        default='tcp://validator:4004')
    parser.add_argument(
        '-t', '--timeout',
        help='set time (in seconds) to wait for a validator response',
        default=500)
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='enable more verbose output to stderr')

    return parser.parse_args(args)


def start_server(host, port, messenger):
    _loop = asyncio.get_event_loop()
    app = web.Application(loop=_loop, client_max_size=20*1024**2)

    app['aes_key'] = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    app['secret_key'] = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    messenger.open_validator_connection()
    handler = RouterHandler(_loop, messenger)

    app.router.add_post('/create_user', handler.create_user)
    app.router.add_post('/login', handler.login)
    app.router.add_post('/create_com', handler.create_com)
    app.router.add_put('/update_com', handler.update_com)
    app.router.add_get('/get_com', handler.get_com)
    app.router.add_post('/create_emp', handler.create_emp)
    app.router.add_put('/update_emp', handler.update_emp)
    app.router.add_get('/get_emp', handler.get_emp)
    app.router.add_get('/get_transactions', handler.get_transactions)

    LOGGER.info('Starting Company Api on %s:%s', host, port)

    web.run_app(
        app,
        host=host,
        port=port,
        access_log=LOGGER,
        access_log_format='%r: %s status, %b size, in %Tf s'
    )


def main():
    loop = ZMQEventLoop()
    asyncio.set_event_loop(loop=loop)

    messenger = None
    try:
        opts = parse_args(sys.argv[1:])
        init_console_logging(verbose_level=opts.verbose)
        validator_url = opts.connect
        if "tcp://" not in validator_url:
            validator_url = "tcp://" + validator_url
        messenger = Messenger(validator_url)

        try:
            host, port = opts.bind.split(":")
            port = int(port)
        except ValueError:
            print("Unable to parse binding {}: Must be in the format host:port".format(opts.blind))
            sys.exit(1)

        start_server(host, port, messenger)
    except Exception as err:
        LOGGER.exception(err)
        sys.exit(1)
    finally:
        if messenger is not None:
            messenger.close_validator_connection()


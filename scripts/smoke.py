#!/usr/bin/env python3
"""Exercise the built CLI and both MCP endpoints against a synthetic loopback guard."""
import argparse
import http.server
import json
import pathlib
import select
import subprocess
import tempfile
import threading

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=pathlib.Path)
args = parser.parse_args()
binary = str(args.binary.resolve())

class Guard(http.server.BaseHTTPRequestHandler):
    calls = 0
    def log_message(self, *_):
        pass
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert request['store'] is False and request['background'] is False
        assert request['tools'] == [] and request['text']['format']['strict'] is True
        Guard.calls += 1
        body = json.dumps({'id': 'resp-smoke', 'model': request['model'], 'status': 'completed',
            'output': [{'type': 'message', 'role': 'assistant', 'content': [
                {'type': 'output_text', 'text': json.dumps({'classification': 'allow_coordination', 'explanation': 'Synthetic scheduling note.'})}]}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('x-request-id', 'req-smoke')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

class Endpoint:
    def __init__(self, root, name, endpoint, protocol):
        self.name = name
        self.protocol = protocol
        self.config = root / (name + '.json')
        self.command = [binary, '--config', str(self.config), '--data-dir', str(root / name)]
        self.cli('init', '--identity', name, '--deployment-id', 'smoke-' + name, '--endpoint', endpoint)
        config = json.loads(self.config.read_text())
        config['guard']['api_key_env'] = ''
        self.config.write_text(json.dumps(config))
        self.key = json.loads(self.cli('identity', 'show', '--json'))['public_key']
        self.process = None
        self.sequence = 0
    def cli(self, *args):
        return subprocess.run(self.command + list(args), check=True, text=True, capture_output=True, timeout=30).stdout
    def start(self):
        self.process = subprocess.Popen(self.command + ['serve'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if self.protocol == '2026-07-28':
            result = self.rpc('server/discover', {})
            assert self.protocol in result['supportedVersions'], result
        else:
            result = self.rpc('initialize', {
                'protocolVersion': self.protocol, 'capabilities': {},
                'clientInfo': {'name': 'turnwire-smoke', 'version': '1'},
            })
            assert result['protocolVersion'] == self.protocol, result
            self.process.stdin.write(json.dumps({
                'jsonrpc': '2.0', 'method': 'notifications/initialized',
            }) + '\n')
            self.process.stdin.flush()
    def rpc(self, method, params):
        self.sequence += 1
        if self.protocol == '2026-07-28':
            params = dict(params, _meta={
                'io.modelcontextprotocol/protocolVersion': self.protocol,
                'io.modelcontextprotocol/clientInfo': {'name': 'turnwire-smoke', 'version': '1'},
                'io.modelcontextprotocol/clientCapabilities': {},
            })
        self.process.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': self.sequence, 'method': method, 'params': params}) + '\n')
        self.process.stdin.flush()
        while True:
            ready, _, _ = select.select([self.process.stdout], [], [], 30)
            if not ready:
                raise TimeoutError('MCP response timed out: ' + method)
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError('MCP exited: ' + self.process.stderr.read())
            response = json.loads(line)
            if response.get('id') == self.sequence:
                assert 'error' not in response, response
                return response['result']
    def tool(self, name, arguments):
        result = self.rpc('tools/call', {'name': name, 'arguments': arguments})
        assert not result.get('isError'), result
        assert result.get('content', []) == [], result
        return result['structuredContent']
    def stop(self):
        if self.process is None:
            return
        self.process.stdin.close()
        try:
            code = self.process.wait(timeout=15)
            assert code == 0, self.process.stderr.read()
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait()
            self.process.stdout.close()
            self.process.stderr.close()
            self.process = None

for protocol in ('2025-11-25', '2026-07-28'):
    Guard.calls = 0
    with tempfile.TemporaryDirectory(prefix='turnwire-smoke-') as temp:
        root = pathlib.Path(temp)
        with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Guard) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            endpoint = 'http://127.0.0.1:' + str(server.server_port) + '/v1/responses'
            work = Endpoint(root, 'work', endpoint, protocol)
            personal = Endpoint(root, 'personal', endpoint, protocol)
            for source, destination in [(work, personal), (personal, work)]:
                source.cli('peer', 'add', destination.name, destination.key)
                assert json.loads(source.cli('doctor', '--probe', '--json'))['ok']
            try:
                work.start()
                personal.start()
                assert len(work.rpc('tools/list', {})['tools']) == 5
                send_args = {'destination': 'personal', 'text': 'Meeting moved to 10:30.', 'request_id': 'smoke-message'}
                sent = work.tool('send_message', send_args)
                assert sent['status'] == 'released'
                received = personal.tool('receive_message', {'envelope': sent['envelope']})
                assert received['status'] == 'accepted'
                confirmed = work.tool('confirm_delivery', {'acknowledgement': received['acknowledgement']})
                assert confirmed['status'] == 'confirmed'
                inbox = personal.tool('list_messages', {})
                assert len(inbox['messages']) == 1 and inbox['messages'][0]['body'] == send_args['text']
                assert work.tool('audit_checkpoint', {})['signature']
                assert work.tool('send_message', send_args) == sent
                assert personal.tool('receive_message', {'envelope': sent['envelope']}) == received
                assert work.tool('confirm_delivery', {'acknowledgement': received['acknowledgement']}) == confirmed
            finally:
                work.stop()
                personal.stop()
            for source in (work, personal):
                assert json.loads(source.cli('log', 'verify', '--json'))['ok']
                export = root / (source.name + '-export.jsonl')
                source.cli('log', 'export', '--output', str(export))
                exported = [json.loads(line) for line in export.read_text().splitlines()]
                assert exported[-1]['kind'] == 'checkpoint'
                assert all('text' not in entry for entry in exported)
            try:
                work.start()
                personal.start()
                assert work.tool('send_message', send_args) == sent
                assert personal.tool('receive_message', {'envelope': sent['envelope']}) == received
                assert work.tool('confirm_delivery', {'acknowledgement': received['acknowledgement']}) == confirmed
                assert len(personal.tool('list_messages', {})['messages']) == 1
            finally:
                work.stop()
                personal.stop()
                server.shutdown()
                thread.join(timeout=5)
            assert Guard.calls == 4, Guard.calls
    print('PASS:', protocol, '- init, pairing, doctor, five MCP tools, signed transfer, retries before/after restart, inbox, audit and redacted export; four loopback guard calls.')

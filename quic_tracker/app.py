#
#   QUIC-Tracker
#   Copyright (C) 2017-2018  Maxime Piraux
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License version 3
#   as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import re
import json
from base64 import b64decode
from datetime import datetime

import yaml
from flask import Flask, jsonify, request, url_for, abort, make_response, redirect
from flask.templating import render_template

from quic_tracker.traces import get_traces, parse_trace, find_similar_trace_idx
from quic_tracker.utils import find_latest_file, ByteArrayEncoder, is_tuple, decode, join_root, find_data_files, \
    find_previous_file, find_next_file, UrlPrefixMiddleware

app = Flask(__name__)
app.json_encoder = ByteArrayEncoder

if 'URL_PREFIX' in os.environ:
    app.wsgi_app = UrlPrefixMiddleware(app.wsgi_app, prefix=os.environ['URL_PREFIX'])

app.jinja_env.filters['is_tuple'] = is_tuple
app.jinja_env.filters['decode'] = decode
app.jinja_env.filters['pretty_json'] = lambda x: json.dumps(x, indent=2, separators=(',', ':'))
app.jinja_env.filters['timestamp'] = lambda x: datetime.fromtimestamp(x)
app.jinja_env.globals['allow_upload'] = os.environ.get('QUIC_TRACKER_ALLOW_UPLOAD', '0') != '0'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['EXPLAIN_TEMPLATE_LOADING'] = True

os.makedirs(join_root('data'), exist_ok=True)
os.makedirs(join_root('traces'), exist_ok=True)


@app.route('/')
def index():
    return redirect(url_for('test_suite'))


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/traces')
def test_suite():
    for f in list(find_data_files('traces')):
        try:
            return traces(int(os.path.splitext(f)[0]))
        except:
            continue
    abort(404)


@app.route('/traces/<int:traces_id>')
def traces(traces_id):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    with open(join_root('scenarii.yaml')) as f:
        scenarii = yaml.load(f)

    return render_template('traces.html', traces_id=traces_id, traces=traces, date=datetime.strptime('{:08d}'.format(traces_id), '%Y%m%d').date(), scenarii=scenarii)


@app.route('/traces/misc/<traces_id>')
def misc_traces(traces_id):
    traces = get_traces(traces_id, misc=True)
    if traces is None:
        abort(404)

    with open(join_root('scenarii.yaml')) as f:
        scenarii = yaml.load(f)

    return render_template('traces.html', traces_id=traces_id, traces=traces, date=datetime.strptime('{:08d}'.format(int(traces_id.split('_')[1])), '%Y%m%d').date(), scenarii=scenarii)


@app.route('/traces/<int:traces_id>/<int:trace_idx>')
def dissector(traces_id, trace_idx):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    with open(join_root('scenarii.yaml')) as f:
        scenarii = yaml.load(f)

    trace = parse_trace(traces[trace_idx])

    try:
        previous_id = (find_previous_file(traces_id, 'traces') or '').replace('.json', '')
        previous_trace_idx = find_similar_trace_idx(trace, get_traces(previous_id))
    except:
        previous_id, previous_trace_idx = None, None

    try:
        next_id = (find_next_file(traces_id, 'traces') or '').replace('.json', '')
        next_trace_idx = find_similar_trace_idx(trace, get_traces(next_id))
    except:
        next_id, next_trace_idx = None, None

    return render_template('dissector.html', trace=trace, scenario=scenarii[trace['scenario']],
                           pcap_link=url_for('trace_pcap', traces_id=traces_id, trace_idx=trace_idx, _external=True) if trace.get('pcap') else None,
                           decrypted_pcap_link=url_for('trace_decrypted_pcap', traces_id=traces_id, trace_idx=trace_idx) if trace.get('decrypted_pcap') else None,
                           qlog_link=url_for('trace_qlog', traces_id=traces_id, trace_idx=trace_idx, _external=True) if trace.get('qlog') else None,
                           previous=url_for('dissector', traces_id=previous_id, trace_idx=previous_trace_idx) if previous_trace_idx is not None else '',
                           next=url_for('dissector', traces_id=next_id, trace_idx=next_trace_idx) if next_trace_idx is not None else '',
                           secrets_link=url_for('trace_secrets', traces_id=traces_id, trace_idx=trace_idx, _external=True) if trace.get('secrets') else None,
                           qvis_list_link=url_for('qvis_list', traces_id=traces_id, host=trace['host'], _external=True))


@app.route('/traces/misc/<traces_id>/<int:trace_idx>')
def dissector_misc(traces_id, trace_idx):
    traces = get_traces(traces_id, misc=True)
    if traces is None:
        abort(404)

    with open(join_root('scenarii.yaml')) as f:
        scenarii = yaml.load(f)

    trace = parse_trace(traces[trace_idx])

    return render_template('dissector.html', trace=trace, scenario=scenarii[trace['scenario']],
                           pcap_link='',
                           decrypted_pcap_link='',
                           qlog_link='',
                           previous='',
                           next='',
                           secrets_link='',
                           qvis_list_link='')


@app.route('/grid')
def latest_grid():
    for f in list(find_data_files('traces')):
        try:
            return grid(int(os.path.splitext(f)[0]))
        except:
            raise
            continue
    abort(404)


scenarii_groups = {
    'Handshake': {
        'handshake',
        'handshake_v6',
        'zero_rtt',
        'transport_parameters',
        'unsupported_tls_version',
        'padding',
        'version_negotiation',
        'address_validation',
        'key_update',
        'spin_bit',
        'zero_length_cid',
        'multi_packet_client_hello',
    },
    'ACKs': {
        'ack_only',
        'ack_ecn',
    },
    'Streams': {
        'http_get_and_wait',
        'http_get_on_uni_stream',
        'multi_stream',
        'stop_sending_frame_on_receive_stream',
        'stream_opening_reordering',
        'flow_control',
        'overlapping_stream_frames',
        'server_flow_control',
    },
    'Migration': {
        'connection_migration',
        'connection_migration_v4_v6',
        'new_connection_id',
        'retire_connection_id',
    },
    'HTTP/3': {
        'http3_get',
        'http3_encoder_stream',
        'http3_uni_streams_limits',
        'http3_reserved_frames',
        'http3_reserved_streams'
    },
    'Others': {
        'closed_connection'
    }
}

scenarii_groups_sorted = ['Handshake', 'ACKs', 'Others', 'Streams', 'Migration', 'HTTP/3']


@app.route('/grid/<int:traces_id>')
def grid(traces_id):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    with open(join_root('scenarii.yaml')) as f:
        scenarii = yaml.load(f)

    scenarii_results = {}

    for i, t in enumerate(traces):
        d = scenarii_results.get(t['scenario'], [])
        d.append((i, t))
        scenarii_results[t['scenario']] = d

    scenarii_sorted = []

    for s in scenarii_groups_sorted:
        scenarii_sorted.extend(sorted(scenarii_groups[s]))

    scenarii_sorted = list(filter(lambda x: x in scenarii_results, scenarii_sorted))

    cells = []
    for s in scenarii_sorted:
        s_traces = sorted(scenarii_results[s], key=lambda t: t[1]['host'])
        cells.append([(i, s, t['host'], t['error_code'], error_class(t['error_code'], scenarii[s])) for i, t in s_traces])

    cells = list(zip(*cells))

    permutation = list(sorted(range(len(cells)), key=lambda x: sum(c == 'success' for *i, c in cells[x]) - sum(c == 'failure' for *i, c in cells[x]), reverse=True))
    cells = [cells[i] for i in permutation]

    return render_template('grid.html', traces_id=traces_id, date=datetime.strptime('{:08d}'.format(traces_id), '%Y%m%d').date(),
                           cells=cells, scenarii=scenarii)


@app.template_filter('error_class')
def error_class(code, scenario):
    error_types = scenario.get('error_types', {})

    if code == 0:
        return 'success'

    if code in (254, 255):
        return 'error'

    for t in error_types:
        if code in error_types[t]:
            return t

    return 'unknown'


if os.environ.get('QUIC_TRACKER_ALLOW_UPLOAD', '0') != '0':
    @app.route('/traces/post', methods=['POST'])
    def post_trace():
        if 'trace' in request.form:
            trace = json.loads(request.form['trace'])
            if type(trace) is list:
                trace = trace[0]

            with open(join_root('scenarii.yaml')) as f:
                scenarii = yaml.load(f)

            trace = parse_trace(trace)

            return render_template('dissector.html', trace=trace, scenario=scenarii[trace['scenario']],
                                   pcap_link=None,
                                   decrypted_pcap_link=None,
                                   qlog_link=None,
                                   previous=None,
                                   next=None,
                                   secrets_link=None)

        return redirect(url_for('index'))


def serve_trace(traces_id, trace, pcap):
    response = make_response(b64decode(pcap))
    response.headers.set('Content-Type', 'application/vnd.tcpdump.pcap')
    response.headers.set('Content-Disposition', 'attachment', filename='{}_{}_{}.pcap'.format(traces_id, trace['scenario'], trace['host'][:trace['host'].rfind(':')]))
    return response


@app.route('/traces/<int:traces_id>/<int:trace_idx>/pcap')
def trace_pcap(traces_id, trace_idx):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    return serve_trace(traces_id, traces[trace_idx], traces[trace_idx]['pcap'])


@app.route('/traces/<int:traces_id>/<int:trace_idx>/decrypted_pcap')
def trace_decrypted_pcap(traces_id, trace_idx):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    return serve_trace(traces_id, traces[trace_idx], traces[trace_idx]['decrypted_pcap'])


secret_labels = {
    (1, False): 'CLIENT_EARLY_TRAFFIC_SECRET',
    (2, False): 'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
    (2, True): 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
    (3, False): 'CLIENT_TRAFFIC_SECRET_0',
    (3, True): 'SERVER_TRAFFIC_SECRET_0',
}


@app.route('/traces/<int:traces_id>/<int:trace_idx>/secrets')
def trace_secrets(traces_id, trace_idx):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    trace = traces[trace_idx]
    secret_log_file = ''
    for s in trace.get('secrets', {}).values():
        if (s['epoch'], True) in secret_labels:
            secret_log_file += '{} {} {}\n'.format(secret_labels[(s['epoch'], True)], b64decode(trace['client_random']).hex(), b64decode(s['read']).hex())
        if (s['epoch'], False) in secret_labels:
            secret_log_file += '{} {} {}\n'.format(secret_labels[(s['epoch'], False)], b64decode(trace['client_random']).hex(), b64decode(s['write']).hex())
    response = make_response(secret_log_file)
    response.headers.set('Content-type', 'text/plain')
    response.headers.set('Content-Disposition', 'attachment', filename='{}_{}_{}.keys'.format(traces_id, trace['scenario'], trace['host'][:trace['host'].rfind(':')]))
    return response


@app.route('/traces/<int:traces_id>/<int:trace_idx>/qt.qlog')
def trace_qlog(traces_id, trace_idx):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    trace = traces[trace_idx]
    return jsonify(trace.get('qlog', {}))


@app.route('/traces/<int:traces_id>/list/<host>')
def qvis_list(traces_id, host):
    traces = get_traces(traces_id)
    if traces is None:
        abort(404)

    host_traces = [(i, t, bool(t.get('qlog'))) for i, t in enumerate(traces) if t['host'] == host and ((t.get('pcap') and t.get('secrets')) or t.get('qlog'))]

    return jsonify({
        'description': 'QUIC-Tracker test results for {} on {}'.format(
            host_traces[0][1]['host'], datetime.fromtimestamp(host_traces[0][1]['started_at']).date()
        ),
        'paths': [
            {'capture': url_for('trace_pcap', traces_id=traces_id, trace_idx=i, _external=True) if not has_qlog else
                        url_for('trace_qlog', traces_id=traces_id, trace_idx=i, _external=True),
             'secrets': url_for('trace_secrets', traces_id=traces_id, trace_idx=i, _external=True) if not has_qlog else '',
             'description': 'QUIC-Tracker {} test for {} on {}'.format(t['scenario'], t['host'], datetime.fromtimestamp(t['started_at']))} for i, t, has_qlog in host_traces
        ]
    })


if __name__ == '__main__':
    app.run(debug=True)

#!/usr/bin/env python
# Copyright 2016 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""Cloud Trace gRPC sample application."""

from __future__ import print_function

import logging
import sys
import time
import uuid

from grpc.beta import implementations
from grpc.framework.interfaces.face.face import NetworkError

from oauth2client import client
from oauth2client.client import GoogleCredentials
from google.protobuf import timestamp_pb2

from google.devtools.cloudtrace.v1 import trace_pb2

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

TRACE_ENDPOINT = "cloudtrace.googleapis.com"
SSL_PORT = 443

"""
Both auth scopes are accepted:
https://www.googleapis.com/auth/cloud-platform

https://www.googleapis.com/auth/trace.readonly
https://www.googleapis.com/auth/trace.append
"""
PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
TRACE_READ_SCOPE = "https://www.googleapis.com/auth/trace.readonly",
TRACE_WRITE_SCOPE = "https://www.googleapis.com/auth/trace.append",

TIMEOUT = 30
USE_PLATFORM_SCOPE = False

def make_auth_func():
    """Creates the callback that provides per rpc auth creds."""

    google_creds = GoogleCredentials.get_application_default()
    scoped_creds = None
    if USE_PLATFORM_SCOPE:
        google_creds.create_scoped([PLATFORM_SCOPE])
    else:
        scoped_creds = google_creds.create_scoped([TRACE_READ_SCOPE, TRACE_WRITE_SCOPE])

    def auth_func():
        """Returns a token obtained from Google Creds."""
        authn = scoped_creds.get_access_token().access_token
        logging.info("Got access_token successfully.")
        return [
            ('authorization', 'Bearer %s' % (authn,))
        ]

    def grpc_auth(dummy_context, callback):
        callback(auth_func(), None)

    return grpc_auth


def create_trace_stub(host=TRACE_ENDPOINT, port=SSL_PORT):
    """Creates a secure channel."""
    ssl_creds = implementations.ssl_channel_credentials(None, None, None)
    call_creds = implementations.metadata_call_credentials(make_auth_func())
    channel_creds = implementations.composite_channel_credentials(ssl_creds, call_creds)
    channel = implementations.secure_channel(host, port, channel_creds)
    return trace_pb2.beta_create_TraceService_stub(channel)


def list_traces(stub, project_id):
    """Lists traces in the given project."""
    trace_id = None
    req = trace_pb2.ListTracesRequest(project_id=project_id)
    try:
        resp = stub.ListTraces(req, TIMEOUT)
        for t in resp.traces:
            trace_id = t.trace_id
            print("Trace is: {}".format(t.trace_id))
    except NetworkError, e:
        logging.warning('Failed to list traces: {}'.format(e))
        sys.exit(1)
    return trace_id


def patch_traces(stub, project_id):
    req = trace_pb2.PatchTracesRequest(project_id=project_id)
    trace_id = str(uuid.uuid1()).replace('-', '')
    now = time.time()

    trace = req.traces.traces.add()
    trace.project_id = project_id
    trace.trace_id = trace_id
    span1 = trace.spans.add()
    span1.span_id = 1
    span1.name = "/span1.{}".format(trace_id)
    span1.start_time.seconds = int(now)-10
    span1.end_time.seconds = int(now)
    
    span2 = trace.spans.add()
    span2.span_id = 2
    span2.name = "/span2"
    span2.start_time.seconds = int(now)-8
    span2.end_time.seconds = int(now)-5

    try:
        resp = stub.PatchTraces(req, TIMEOUT)
        print("Trace added successfully.\n"
              "To view list of traces, go to: "
              "http://console.cloud.google.com/traces/traces?project={}&tr=2\n"
              "To view this trace added, go to: "
              "http://console.cloud.google.com/traces/details/{}?project={}"
              .format(project_id, trace_id, project_id))
    except NetworkError, e:
        logging.warning('Failed to patch traces: {}'.format(e))
        sys.exit(1)


def get_trace(stub, project_id, trace_id):
    req = trace_pb2.GetTraceRequest(project_id=project_id,
                                    trace_id=trace_id)
    try:
        resp = stub.GetTrace(req, TIMEOUT)
        print("Trace retrieved: {}".format(resp))
    except NetworkError, e:
        logging.warning('Failed to get trace: {}'.format(e))
        sys.exit(1)

def usage():
    """Prints usage to the stderr."""
    print('{} project_id'.format(sys.argv[0]), file=sys.stderr)


def main():
    if len(sys.argv) < 2:
        usage()
        exit(1)
    stub = create_trace_stub()
    project_id = sys.argv[1]
    trace_id = list_traces(stub, project_id)
    if trace_id:
        get_trace(stub, project_id, trace_id)

    patch_traces(stub, project_id) 

if __name__ == '__main__':
    main()

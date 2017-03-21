# e3 jupyter kernel for the EulerX Toolkit
# author: Thomas Rodenhausen
#
# Adapted from https://github.com/dsblank/simple_kernel.py
# by Doug Blank <doug.blank@gmail.com>

from __future__ import print_function

import sys
import json
import hmac
import uuid
import errno
import hashlib
import datetime
import threading
from pprint import pformat
import zmq
from zmq.eventloop import ioloop, zmqstream
from zmq.error import ZMQError
from subprocess import Popen, PIPE, call
from shutil import copyfile
import os


PYTHON3 = sys.version_info.major == 3

#Globals:
DELIM = b"<IDS|MSG>"

debug_level = 3 # 0 (none) to 3 (all) for various levels of detail
exiting = False
engine_id = str(uuid.uuid4())
config = {}

def copy_file_to_notebook_dir(code, file):
    filename = os.path.basename(file)
    if filename.startswith("cleantax_"):
        filename = filename.replace("cleantax_", "", 1)
    tapNameAndId = os.path.basename(os.path.dirname(os.path.dirname(file)))
    type = "misc"
    outputTypes = ["graph tap", "graph summary", "graph ambiguity", "graph worlds", "graph four in one", "graph inconsistency"]
    for outputType in outputTypes:
        if code.startswith(outputType):
            type = outputType
    #if code.startswith("graph tap"):
    #    outputType = "graph tap"
    #elif code.startswith("graph summary"):
    #    outputType = "graph summary"
    #elif code.startswith("graph ambiguity"):
    #    pass
    #elif code.startswith("graph worlds"):
    #    pass
    #elif code.startswith("graph four in one"):
    #    pass
    #elif code.startswith("graph inconsistency"):
    #    pass
    
    #newpath = r'C:\Program Files\arbitrary' 
    destination = os.path.join(config['notebook_dir'], 'taps', tapNameAndId, type)
    if not os.path.exists(destination):
        os.makedirs(destination)
    dprint(1, "copy now from " + file + " to " + os.path.join(destination, filename))
    copyfile(file, os.path.join(destination, filename))

# Utility functions:
def shutdown():
    global exiting
    exiting = True
    ioloop.IOLoop.instance().stop()

def dprint(level, *args, **kwargs):
    """ Show debug information """
    if level <= debug_level:
        print("DEBUG:", *args, **kwargs)
        sys.stdout.flush()

def msg_id():
    """ Return a new uuid for message id """
    return str(uuid.uuid4())

def str_to_bytes(s):
    return s.encode('ascii') if PYTHON3 else bytes(s)

def sign(msg_lst):
    """
    Sign a message with a secure signature.
    """
    h = auth.copy()
    for m in msg_lst:
        h.update(m)
    return str_to_bytes(h.hexdigest())

def new_header(msg_type):
    """make a new header"""
    return {
            "date": datetime.datetime.now().isoformat(),
            "msg_id": msg_id(),
            "username": "kernel",
            "session": engine_id,
            "msg_type": msg_type,
            "version": "5.0",
        }

def send(stream, msg_type, content=None, parent_header=None, metadata=None, identities=None):
    header = new_header(msg_type)
    if content is None:
        content = {}
    if parent_header is None:
        parent_header = {}
    if metadata is None:
        metadata = {}

    def encode(msg):
        return str_to_bytes(json.dumps(msg))

    msg_lst = [
        encode(header),
        encode(parent_header),
        encode(metadata),
        encode(content),
    ]
    signature = sign(msg_lst)
    parts = [DELIM,
             signature,
             msg_lst[0],
             msg_lst[1],
             msg_lst[2],
             msg_lst[3]]
    if identities:
        parts = identities + parts
    dprint(3, "send parts:", parts)
    stream.send_multipart(parts)
    stream.flush()

def run_thread(loop, name):
    dprint(2, "Starting loop for '%s'..." % name)
    while not exiting:
        dprint(2, "%s Loop!" % name)
        try:
            loop.start()
        except ZMQError as e:
            dprint(2, "%s ZMQError!" % name)
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        except Exception:
            dprint(2, "%s Exception!" % name)
            if exiting:
                break
            else:
                raise
        else:
            dprint(2, "%s Break!" % name)
            break

def heartbeat_loop():
    dprint(2, "Starting loop for 'Heartbeat'...")
    while not exiting:
        dprint(3, ".", end="")
        try:
            zmq.device(zmq.FORWARDER, heartbeat_socket, heartbeat_socket)
        except zmq.ZMQError as e:
            if e.errno == errno.EINTR:
                continue
            else:
                raise
        else:
            break


# Socket Handlers:
def shell_handler(msg):
    global execution_count
    dprint(1, "shell received:", msg)
    position = 0
    identities, msg = deserialize_wire_msg(msg)

    # process request:

    if msg['header']["msg_type"] == "execute_request":
        dprint(1, "e3 kernel Executing:", pformat(msg['content']["code"]))
        print(sys.path)
        #### In case of user's change of configration or reset:
        ### Force showOutputFileLocation config parameter to assure kernel's display of images to work correctly
        p = Popen("e3 set config showOutputFileLocation = True", stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        dprint(1, stdout)
        dprint(1, stderr)
        ### Force svg output image file format
        p = Popen("e3 set config imageFormat = svg", stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        dprint(1, stdout)
        dprint(1, stderr)

    # --> send busy response
        content = {
            'execution_state': "busy",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
        #################################
        code = msg['content']['code']
        e3Command = "e3 " + code
        
        #escape characters of e3 commands that bash does not like
        import re
        match = re.match('^.*(".*").*$', e3Command)
        if match:
            term = match.group(1)
            replacement = "'" + term + "'"
            e3Command = e3Command.replace(term, replacement)
        e3Command = e3Command.replace('(', '\(')
        e3Command = e3Command.replace(')', '\)')
        dprint(1, "e3Command: " + e3Command)
        p = Popen(e3Command, stdout=PIPE, stderr=PIPE, shell=True)
        stdout, stderr = p.communicate()
        stdout = stdout.decode()
        stderr = stderr.decode()
        dprint(1, stdout)
        dprint(1, stderr)
        
        userOut = []
        filesOut = []
        files = False
        for line in stdout.split('\n'):
            if line == "Files:":
                files = True
                continue
            if files:
                filesOut.append(line)
            else:
                userOut.append(line)
                
        #######################################################################
        content = {
            'execution_count': execution_count,
            'code': msg['content']["code"],
        }
        send(iopub_stream, 'execute_input', content, parent_header=msg['header'])
        #######################################################################
        #content = {
        #    'name': "stdout",
        #    'text': "hello, world",
        #}
        #send(iopub_stream, 'stream', content, parent_header=msg['header'])
        #######################################################################
        content = {
            'execution_count': execution_count,
            'data': {"text/plain": '\n'.join(userOut)},
            'metadata': {}
        }
        send(iopub_stream, 'execute_result', content, parent_header=msg['header'])
        #######################################################################
        
        
        result = ""
        if filesOut:
            for file in filesOut:
                if file.endswith('.svg'):
                    #copy_file_to_notebook_dir(code, file)
                    with open(file) as f: 
                        image = f.read()
                        content = {
                            'execution_count': execution_count,
                            'data': {"image/svg+xml": image},
                            'metadata': {}
                        }
                        send(iopub_stream, 'execute_result', content, parent_header=msg['header'])
                #if file.endswith('.pdf'):
                    #copy_file_to_notebook_dir(code, file)
                    
                    #with open(file) as f: 
                    #    image = f.read()
                    #    content = {
                    #        'execution_count': execution_count,
                    #        'data': {"application/pdf": image},
                    #        'metadata': {}
                    #    }
                    #    send(iopub_stream, 'execute_result', content, parent_header=msg['header'])
        #######################################################################
        content = {
            'execution_state': "idle",
        }
        send(iopub_stream, 'status', content, parent_header=msg['header'])
        #######################################################################
        metadata = {
            "dependencies_met": True,
            "engine": engine_id,
            "status": "ok",
            "started": datetime.datetime.now().isoformat(),
        }
        content = {
            "status": "ok",
            "execution_count": execution_count,
            "user_variables": {},
            "payload": [],
            "user_expressions": {},
        }
        send(shell_stream, 'execute_reply', content, metadata=metadata,
            parent_header=msg['header'], identities=identities)
        execution_count += 1
    elif msg['header']["msg_type"] == "kernel_info_request":
        content = {
            "protocol_version": "5.0",
            "ipython_version": [1, 1, 0, ""],
            "language_version": [0, 0, 1],
            "language": "e3",
            "implementation": "e3",
            "implementation_version": "1.1",
            "language_info": {
                "name": "e3",
                "version": "1.0",
                'mimetype': "",
                'file_extension': ".py",
                'pygments_lexer': "",
                'codemirror_mode': "",
                'nbconvert_exporter': "",
            },
            "banner": ""
        }
        send(shell_stream, 'kernel_info_reply', content, parent_header=msg['header'], identities=identities)
    elif msg['header']["msg_type"] == "history_request":
        dprint(1, "unhandled history request")
    else:
        dprint(1, "unknown msg_type:", msg['header']["msg_type"])

def deserialize_wire_msg(wire_msg):
    """split the routing prefix and message frames from a message on the wire"""
    delim_idx = wire_msg.index(DELIM)
    identities = wire_msg[:delim_idx]
    m_signature = wire_msg[delim_idx + 1]
    msg_frames = wire_msg[delim_idx + 2:]

    def decode(msg):
        return json.loads(msg.decode('ascii') if PYTHON3 else msg)

    m = {}
    m['header']        = decode(msg_frames[0])
    m['parent_header'] = decode(msg_frames[1])
    m['metadata']      = decode(msg_frames[2])
    m['content']       = decode(msg_frames[3])
    check_sig = sign(msg_frames)
    if check_sig != m_signature:
        raise ValueError("Signatures do not match")

    return identities, m

def control_handler(wire_msg):
    global exiting
    dprint(1, "control received:", wire_msg)
    identities, msg = deserialize_wire_msg(wire_msg)
    # Control message handler:
    if msg['header']["msg_type"] == "shutdown_request":
        shutdown()

def iopub_handler(msg):
    dprint(1, "iopub received:", msg)

def stdin_handler(msg):
    dprint(1, "stdin received:", msg)

def bind(socket, connection, port):
    if port <= 0:
        return socket.bind_to_random_port(connection)
    else:
        socket.bind("%s:%s" % (connection, port))
    return port

## Initialize:
ioloop.install()

if len(sys.argv) > 1:
    dprint(1, "Loading e3-kernel with args:", sys.argv)
    dprint(1, "Reading config file '%s'..." % sys.argv[1])
    config = json.loads("".join(open(sys.argv[1]).readlines()))
else:
    dprint(1, "Starting e3-kernel with default args...")
    config = {
        'control_port'      : 0,
        'hb_port'           : 0,
        'iopub_port'        : 0,
        'ip'                : '127.0.0.1',
        'key'               : str(uuid.uuid4()),
        'shell_port'        : 0,
        'signature_scheme'  : 'hmac-sha256',
        'stdin_port'        : 0,
        'transport'         : 'tcp'
    }

if len(sys.argv) > 2:
    config['notebook_dir'] = sys.argv[2]
else:
    config['notebook_dir'] = os.path.expanduser("~")

connection = config["transport"] + "://" + config["ip"]
secure_key = str_to_bytes(config["key"])
signature_schemes = {"hmac-sha256": hashlib.sha256}
auth = hmac.HMAC(
    secure_key,
    digestmod=signature_schemes[config["signature_scheme"]])
execution_count = 1

##########################################
# Configure e3:
p = Popen("e3 clear history", stdout=PIPE, stderr=PIPE, shell=True)
stdout, stderr = p.communicate()
dprint(1, stdout)
dprint(1, stderr)

p = Popen("e3 set config showOutputFileLocation = True", stdout=PIPE, stderr=PIPE, shell=True)
stdout, stderr = p.communicate()
dprint(1, stdout)
dprint(1, stderr)
        


##########################################
# Heartbeat:
ctx = zmq.Context()
heartbeat_socket = ctx.socket(zmq.REP)
config["hb_port"] = bind(heartbeat_socket, connection, config["hb_port"])

##########################################
# IOPub/Sub:
# aslo called SubSocketChannel in IPython sources
iopub_socket = ctx.socket(zmq.PUB)
config["iopub_port"] = bind(iopub_socket, connection, config["iopub_port"])
iopub_stream = zmqstream.ZMQStream(iopub_socket)
iopub_stream.on_recv(iopub_handler)

##########################################
# Control:
control_socket = ctx.socket(zmq.ROUTER)
config["control_port"] = bind(control_socket, connection, config["control_port"])
control_stream = zmqstream.ZMQStream(control_socket)
control_stream.on_recv(control_handler)

##########################################
# Stdin:
stdin_socket = ctx.socket(zmq.ROUTER)
config["stdin_port"] = bind(stdin_socket, connection, config["stdin_port"])
stdin_stream = zmqstream.ZMQStream(stdin_socket)
stdin_stream.on_recv(stdin_handler)

##########################################
# Shell:
shell_socket = ctx.socket(zmq.ROUTER)
config["shell_port"] = bind(shell_socket, connection, config["shell_port"])
shell_stream = zmqstream.ZMQStream(shell_socket)
shell_stream.on_recv(shell_handler)

dprint(1, "Config:", json.dumps(config))
dprint(1, "Starting loops...")

hb_thread = threading.Thread(target=heartbeat_loop)
hb_thread.daemon = True
hb_thread.start()

dprint(1, "Ready! Listening...")

ioloop.IOLoop.instance().start()

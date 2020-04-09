import sys, signal, socket, string, multiprocessing, requests, hashlib, optparse

use_VT = True # Artifact from before my VirusTotal implementation
host = 'localhost'
portNum = 2100

#Command line options parser
parser = optparse.OptionParser()
parser.add_option('-k', '--key', dest='API_key', type='string',
                  help='Specify API key with \'-k\' \'key\'')

options, args = parser.parse_args()
if len(args) == 1: #Another artifact so you can specify your own port
    portNum = int(args[0])
elif len(args) > 1:
    print("Too many arguments given")
    exit()
API_key = options.API_key

#Handler for VirusTotal API: takes the pre-calculated md5 checksum
# of a file, iterates the json data returned by VirusTotal;
# returns True if possible virus; False otherwise
def VT_handler(md5_string):
    params = {'apikey': API_key, 'resource': md5_string}
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    response = requests.get(url, params=params).json()

    for key in response.keys():
        if key == 'scans':
            scanners = response["scans"].keys()
            for scanner in scanners:
                if response["scans"][scanner]["detected"] is True:
                    return True
    return False

#Ctl-C handler
def interrupt_handler(sigint, frame):
    print("\nInterrupt detected")
    exit(0)
signal.signal(signal.SIGINT, interrupt_handler)

#Formula for 501 and 400 responses, in case of request error
def bad_response(conn, is_501):
    response = ''
    if is_501 is False:
        response = 'HTTP/1.0 400 Bad Request\r\nContent-Type: text/html; encoding=utf8\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
    else:
        response = 'HTTP/1.0 501 Not Implemented\r\nContent-Type: text/html; encoding=utf8\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
    conn.sendall(bytes(response.encode('utf8')))
    conn.shutdown(socket.SHUT_RDWR)
    conn.close()
    exit()

# Create socket between client and proxy
listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    listenSocket.bind((host, portNum))
except:
    print("Could not bind to this port or host. The port may already be in use.")
    exit()

# Start listening for connections
listenSocket.listen(100)
def listen():
    while True:
        conn, addr = listenSocket.accept()
        print("Connection accepted")
        client = multiprocessing.Process(target=listenGET, args=(conn,))
        client.daemon = True #Spawn new daemon process per connected client
        client.start()

# Start listening for GET message from client
def listenGET(conn):
    request = conn.recv(2048)
    params = []
    
    #First check to see if we have entire request in one recv
    if str(request).endswith('\r\n\r\n'):
        parseRequest(request, conn, params)
    elif str(request).endswith('\n\n'):
        parseRequest(request, conn, params)

    #Otherwise, keep receiving body until we have entire request
    while True:
        param = conn.recv(2048)
        if param == bytes('\r\n'.encode('utf-8')):
            break
        params.append(param)

    parseRequest(request, conn, params)

# Parses info (headers) from request message.
def parseRequest(requestBytes, conn, params):
    #Check to ensure parameters are properly formatted
    for param in params:
        if len(param.decode('utf8').split(':')) is not 2:
            bad_response(conn, False)

    bytes_request = requestBytes
    string_request = ''
    try:
        string_request = requestBytes.decode('utf8')
    except:
        print("Something went wront - client probably disconnected")
        exit()
    requestArr = string_request.split()

    #Check to ensure the client didn't make a poor request
    if len(requestArr) < 3:
        bad_response(conn, False)

    if len(requestArr[1].split('//')) < 2:
        bad_response(conn, False)
        
    if requestArr[0] != "GET":
        bad_response(conn, True)

    requestUrlStr = requestArr[1].split(':') #Obtain URL portions
    try:
        requestHost = requestArr[1].split('//')[1]
    except:
        print("URL was not entered correctly")
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        exit()
        
    requestHost = requestHost.split('/')[0] #Obtain hostname from URL
    if (requestHost.endswith('/')):
        requestHost = requestHost[:-1] #Trim last '/' from hostname

    #Determine whether or not client specified port in URL
    if len(requestUrlStr) == 3:
        requestPort = int(requestUrlStr[2].split('/')[0])
    else:
        requestPort = 80

    #Accept both 1.0 and 1.1 as protocol version
    if requestArr[2] != "HTTP/1.0" and requestArr[2] != "HTTP/1.1":
        bad_response(conn, False)

    connectRemote(bytes_request, requestHost, requestPort, conn, params)

#Once all info from client request has been parsed, connect to the remote host
# using that info
def connectRemote(requestB, hostname, port, conn, params):
    remoteSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remoteRequest = ''
    reqeustPath = ''
    requestArr = requestB.decode('utf8').split()
    
    #Ensure the path we're building starts with
    #(or is at least) '/'
    if len(requestArr[1].split(hostname)) is 1:
        requestPath = '/'
    else:
        if requestArr[1].split(hostname)[1] is u'':
            requestPath = '/'
        else:
            requestPath = requestArr[1].split(hostname)[1].split()[0]
    if len(requestArr) < 3: #In any request, there must be at least two spaces in first line 
        bad_response(conn, False)

    if requestPath.startswith('/'):
        remoteRequest = 'GET ' + requestPath + ' ' + 'HTTP/1.0\r\n'
    else:
        remoteRequest = 'GET /' + requestPath + ' ' + 'HTTP/1.0\r\n'

    hardCode_params = "Host: " + hostname.split(':')[0] + "\r\nConnection: close\r\n"

    params_to_send = []

    #Add parameters to header from client to send to remote host
    for param in params:
        param_str = param.decode('utf8')
        if param_str.split(':')[0] == 'Connection': #Ensure this is Connection: close 
            continue
        else:
            params_to_send.append(bytes(param_str.encode('utf8')))

    remoteRequestBytes = bytes((remoteRequest + hardCode_params).encode('utf8'))

    #Connect to the remote server, send all the data just built
    hostname = hostname.split(':')[0]
    try:
        remoteSocket.connect((hostname, port))
        remoteSocket.sendall(remoteRequestBytes)
        for param in params:
            remoteSocket.sendall(param)
        remoteSocket.sendall(bytes('\r\n'.encode('utf-8')))
    except socket.error:
        print("Something went wrong trying to connect and/or send request to remote host")
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        exit()

    #Begin receiving response from the server
    try:
        line = remoteSocket.recv(4096)
    except socket.error:
        print("Could not receive response from remote host")
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        exit()
        
    if len(line) > 0:
        line_adjusted = line[:12]
        is_ok = line_adjusted.decode('utf-8').split()[1]
        raw_response = u''
        md5 = hashlib.md5()
        byte_list = []
        
        if is_ok == '200':
            if use_VT == False:
                try:
                    conn.sendall(line)
                except:
                    print("Could not send data back to client")
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                    exit()
            else:
                #Horrible way to go about finding the body of the response
                #without breaking the server, but it works! (Had to do this
                #because I don't know when utf-8 encoding ends and other
                #encodings begin)
                byte_list.append(line)
                i = 0
                while i < len(line):
                    if (line[i-4:i]).decode('utf-8') == '\r\n\r\n':
                        print(line)
                        raw_response = line[i:]
                        md5.update(raw_response)
                        break
                    i += 1

                #Make sure we capture the rest of the body to check with VirusTotal
                while True:
                    line = u''
                    try:
                        line = remoteSocket.recv(1024)
                    except:
                        print("Could not receive data from remote server")
                        conn.shutdown(socket.SHUT_RDWR)
                        conn.close()
                        exit()
                        
                    if len(line) > 0:
                        md5.update(line)
                        byte_list.append(line)
                    else:
                        break

                #Pass the md5 checksum to VirusTotal handler
                if VT_handler(md5.hexdigest()) is False: #Probably Virus free!
                    for line in byte_list:
                        try:
                            conn.sendall(line)
                        except:
                            print("Could not send data back to client")
                            conn.shutdown(socket.SHUT_RDWR)
                            conn.close()
                            exit()
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                    exit()
                else: # Virus found: Return "content blocked"
                    html_msg = bytes('content blocked\n'.encode('utf8'))
                    html_len = len(html_msg)
                    response = bytes(('HTTP/1.0 200 OK\r\nContent-Type: text/html; encoding=utf8\r\nContent-Length: ' + str(html_len) + '\r\nConnection: close\r\n\r\n').encode('utf8'))
                    try:
                        conn.sendall(response)
                        conn.sendall(html_msg)
                    except:
                        print("Could not send positive virus result")
                    finally:
                        conn.shutdown(socket.SHUT_RDWR)
                        conn.close()
                        exit()
                
        else:
            #Response was not '200 OK' - send response to client, anyway
            try:
                conn.sendall(line)
            except:
                print("Could not send data back to client")
                conn.shutdown(socket.SHUT_RDWR)
                conn.close()
                exit()
            while True:
                try:
                    line = remoteSocket.recv(1024)
                    if line:
                        conn.sendall(line)
                    else:
                        break
                except:
                    print("Something went wrong trying to receive from host or send to client")
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                    exit()

            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            exit()
            
#Script to start up the server!
listen()

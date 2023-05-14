# Libraries used:
import socket, sys, signal, threading, select

# Where the blocked sites are stored:
blocked = ["tcd.blackboard.com", "youtube.com"]

number = 0  # connection count

config = {
    "HOST": "localhost",
    "PORT": 8080,
    
    "MAX_CONNECTIONS": 40,
    "BUFFER_SIZE": 4092,  # max number of bytes that can be received at once for http
}

# Function: Initialise program
# Description: Creates sockets and binds and listens to the server
#              Listens to the clients, accepting the connection and creating a new socket object
#              Generates multi-threads for the connections and keeps of track of how many threads are active
def init():
    global number

    # Shutdown on Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    continueOn = True
    print("Serving on: " + str(config['PORT']))

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create socket
        s.bind((config['HOST'], config['PORT']))  # binds to listener
        s.listen(config['MAX_CONNECTIONS'])  # enables to server to accept up to 20 connections

    except socket.error as e:  # error-checking
        print(str(e))
        print("Failed to initialise socket.")
        sys.exit(1)

    # listens to clients
    while number <= config['MAX_CONNECTIONS'] and continueOn:
        if (number < config['MAX_CONNECTIONS']):
            number = number + 1
            conn, client_address = s.accept()   # accepts a connection, conn becomes new socket obj
            thread = threading.Thread(name=client_address, target = proxy, args=(conn,client_address))
            thread.setDaemon(True)
            thread.start()
            print("Number of threads: "+  str(threading.active_count()))
            print("New connection. Total number of connections: " + str(number) + "\n")

# Function: Signal handler
# Description: Checks for KeyInterruption Ctrl+C from user
def signal_handler(signal, frame):
    print("Interruption.")
    sys.exit(0)


# Function: Handle requests to and from browser
# Description: Deals with HTTP and HTTPS requests
#              Checks for blocked URLS
def proxy(conn, client_address):
    global number
    data = conn.recv(config["BUFFER_SIZE"])  # get type of request from browser
    url_blocked = False
    empty = b''

    if data is not empty:

        try:
            first_line = data.decode().split('\n')[0]  # parse the first line

            try:
                url = first_line.split(' ')[1]  # get URL
                type = ""

                if "CONNECT" in first_line:
                    type = "https"

                else:
                    type = "http"

                # ------------- HANDLING BLOCKED URLS -------------#
                for i in range(0, len(blocked)):  # check if site is already blocked

                    if blocked[i] in url:
                        print("Blocked URL site: " + url + "\n")
                        url_blocked = True
                        conn.close()

                # ------------- END OF HANDLING BLOCKED URLS -------------#

                if url_blocked is False:
                    print("Request: ", first_line, client_address)

                    # get webserver and port
                    http_position = url.find("://")

                    if (http_position == -1):
                        temp = url

                    elif (type == "http"):
                        # get the rest of the URL
                        temp = url[(http_position + 3):]

                    else:
                        # get the rest of the URL
                        temp = url[(http_position + 4):]

                    # find the port position if any
                    port_position = temp.find(":")

                    # find the end of web server
                    webserver_position = temp.find("/")
                    if webserver_position == -1:
                        webserver_position = len(temp)

                    webserver = ""
                    port = -1

                    # print(port_position)
                    # print(webserver_position)

                    # ------ setting up the ports and web-servers ------#
                    if (port_position == -1 or webserver_position < port_position):
                        if (type == "https"):
                            port = 443
                        else:
                            port = 80
                        webserver = temp[:webserver_position]
                    else:
                        port = int((temp[(port_position + 1):])[:webserver_position - port_position - 1])
                        webserver = temp[:port_position]

                    print("Connect to: ", webserver, port,  "\n")

                    #--- create socket to connect to the web server ----#
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((webserver, port))

                    # ------------- HANDLING HTTP REQUESTS -------------#
                    if type == "http":
                        s.send(data)  # send request to web server

                        while True:
                            try:
                                server_data = s.recv(config["BUFFER_SIZE"])

                            except socket.error:
                                print("Connection timeout")
                                s.close()
                                conn.close()
                                number = number - 1

                            if (len(server_data) > 0):
                                conn.send(server_data)  # send to browser

                            else:
                                conn.close()
                                s.close()
                                number = number - 1

                    # ------------- HANDLING HTTP REQUESTS ------------ #
                    if type == "https":
                        conn.send(bytes("HTTP/1.1 200 Connection Established\r\n\r\n","utf8")) # send response to the browser

                        connections = [conn , s]     # store both sockets: browser and server
                        keep_connection = True

                        while keep_connection:
                            keep_connection = False
                            ready_sockets, sockets_for_writing, error_sockets = select.select(connections, [], connections, 100)

                            if error_sockets:
                                break

                            for r_socket in ready_sockets:
                                other = connections[1] if r_socket is connections[0] else connections[0]   # look for a ready socket

                                try:
                                    data = r_socket.recv(8192)         # buffer size for HTTPS

                                except socket.error:                    # error-checking
                                    print("Connection timeout")
                                    r_socket.close()

                                if data:
                                    other.sendall(data)
                                    keep_connection = True

                    else:
                        pass

                    # ------------------------------------------------ #

            except IndexError:
                pass

        except UnicodeDecodeError:
            pass

    else:
        pass

    number = number - 1
    conn.close()            # close client connection

def main():
    init()

if __name__ == '__main__':
    main()
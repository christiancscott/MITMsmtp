#!/usr/bin/env python3

from SMTPServer import ThreadedSMTPServer
from SMTPHandler import SMTPHandler
import threading
import os
import argparse
import signal
import sys

"""
MITMsmtp class for user interaction
"""
class MITMsmtp:
    """ Creates a new MITMsmtp object
    @param server_address: The address to listen on
    @type server_address: str
    @param port: Port to listen on
    @type port: int
    @param server_name: Servers FQDN to send to client
    @type server_address: str
    @param authHandler: The authHandler Object which contains the supported authentication methods
    @type authHandler: authHandler
    @param messageHandler: The messageHandler Object which will be used for storing messages
    @type messageHandler: messageHandler
    @param STARTTLS: Enable server support for STARTTLS (not compatible with SSL/TLS)
    @type STARTTLS: bool
    @param SSL: Enable server support for SSL/TLS (not compatible with STARTTLS)
    @type SSL: bool
    @param certfile: Path to the certfile to be used
    @type certfile: str
    @param keyfile: Path to the keyfile to be used
    @type keyfile: str
    @param printLines: Print communication between client and server on command line
    @type printLines: bool

    @return: Returns a new SMTPServer object
    """
    def __init__(self,
                    server_address,
                    port,
                    server_name,
                    authHandler,
                    messageHandler,
                    STARTTLS=False,
                    SSL=False,
                    certfile=None,
                    keyfile=None,
                    printLines=False):
        self.server_address = server_address
        self.port = port
        self.server_name = server_name
        self.authHandler = authHandler
        self.messageHandler = messageHandler
        self.STARTTLS = STARTTLS
        self.SSL = SSL
        self.certfile = certfile
        self.keyfile = keyfile
        self.printLines = printLines
        self.SMTPServer = None
        self.thread = None

    """
    Starts MITMsmtp Server
    """
    def start(self):
        if (self.thread == None):
            if (self.SSL or self.STARTTLS):
                if (self.certfile == None or self.keyfile == None): #Use default certificates if not specified
                    print("[INFO] Using default certificates")
                    self.certfile = os.path.dirname(os.path.realpath(__file__)) + "/certs/MITMsmtp.crt"
                    self.keyfile = os.path.dirname(os.path.realpath(__file__)) + "/certs/MITMsmtp.key"

            self.SMTPServer = ThreadedSMTPServer((self.server_address, self.port),
                                            self.server_name,
                                            SMTPHandler,
                                            self.authHandler,
                                            self.messageHandler,
                                            self.certfile,
                                            self.keyfile,
                                            self.STARTTLS,
                                            self.SSL,
                                            self.printLines)

            self.thread = threading.Thread(target=self.SMTPServer.serve_forever)
            self.thread.start()
        else:
            raise ValueError("SMTPServer is already running")

    """
    Stops MTIMsmtp Server
    """
    def stop(self):
        if (self.SMTPServer != None and self.thread != None):
            self.SMTPServer.shutdown()
            self.thread.join()
            self.thread = None
            self.SMTPServer.server_close()
        else:
            raise ValueError("MITMsmtp is currently not running")

# Simple placeholder classes - you'll need to replace these with your actual implementations
class SimpleAuthHandler:
    def toString(self):
        return "PLAIN LOGIN"
    
    def matchMethod(self, line):
        # Simple implementation - you'll need your actual auth logic
        return SimpleAuth
        
class SimpleAuth:
    def __init__(self, handler, line):
        self.username = "test"
        self.password = "test"
    
    def getUsername(self):
        return self.username
    
    def getPassword(self):
        return self.password

class SimpleMessageHandler:
    def addMessage(self):
        return SimpleMessage()

class SimpleMessage:
    def __init__(self):
        self.clientIP = ""
        self.client_name = ""
        self.sender = ""
        self.recipients = []
        self.message = ""
        self.username = ""
        self.password = ""
        
    def setClientIP(self, ip):
        self.clientIP = ip
        
    def setClientName(self, name):
        self.client_name = name
        
    def setSender(self, sender):
        self.sender = sender
        print(f"[INFO] Sender: {sender}")
        
    def addRecipient(self, recipient):
        self.recipients.append(recipient)
        print(f"[INFO] Recipient: {recipient}")
        
    def setMessage(self, message):
        self.message = message
        print(f"[INFO] Message captured ({len(message)} bytes)")
        
    def setLogin(self, username, password):
        self.username = username
        self.password = password
        print(f"[INFO] Login captured - Username: {username}, Password: {password}")
        
    def setComplete(self):
        print(f"[INFO] Message complete from {self.sender} to {self.recipients}")

def signal_handler(sig, frame):
    print('\n[INFO] Shutting down...')
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='MITMsmtp - SMTP Man-in-the-Middle Server')
    parser.add_argument('--port', type=int, default=587, help='Port to listen on (default: 587)')
    parser.add_argument('--server_address', default='0.0.0.0', help='Address to bind to (default: 0.0.0.0)')
    parser.add_argument('--server_name', default='mail.example.com', help='Server name to present to clients')
    parser.add_argument('--log', help='Log file (currently not implemented)')
    parser.add_argument('--STARTTLS', action='store_true', help='Enable STARTTLS support')
    parser.add_argument('--SSL', action='store_true', help='Enable SSL/TLS support')
    parser.add_argument('--certfile', help='SSL certificate file')
    parser.add_argument('--keyfile', help='SSL key file')
    parser.add_argument('--print-lines', action='store_true', help='Print client-server communication')
    
    args = parser.parse_args()
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create handlers
    auth_handler = SimpleAuthHandler()
    message_handler = SimpleMessageHandler()
    
    # Create and start the MITM SMTP server
    mitm_server = MITMsmtp(
        server_address=args.server_address,
        port=args.port,
        server_name=args.server_name,
        authHandler=auth_handler,
        messageHandler=message_handler,
        STARTTLS=args.STARTTLS,
        SSL=args.SSL,
        certfile=args.certfile,
        keyfile=args.keyfile,
        printLines=args.print_lines
    )
    
    try:
        print(f"[INFO] Starting MITMsmtp server on {args.server_address}:{args.port}")
        if args.STARTTLS:
            print("[INFO] STARTTLS enabled")
        if args.SSL:
            print("[INFO] SSL/TLS enabled")
        
        mitm_server.start()
        print("[INFO] Server started. Waiting for connections...")
        print("[INFO] Press Ctrl+C to stop")
        
        # Keep the main thread alive
        while True:
            try:
                import time
                time.sleep(1)
            except KeyboardInterrupt:
                break
                
    except Exception as e:
        print(f"[ERROR] Failed to start server: {e}")
    finally:
        try:
            mitm_server.stop()
            print("[INFO] Server stopped")
        except:
            pass

if __name__ == "__main__":
    main()
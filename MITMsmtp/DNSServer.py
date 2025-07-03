#!/usr/bin/env python3

import socket
import struct
import threading
import time

class DNSServer:
    """
    Simple DNS server that responds to all queries with a specified IP address
    """
    
    def __init__(self, listen_address='0.0.0.0', listen_port=53, response_ip='127.0.0.1', print_queries=False):
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.response_ip = response_ip
        self.print_queries = print_queries
        self.running = False
        self.socket = None
        self.thread = None
    
    def start(self):
        """Start the DNS server"""
        if self.running:
            raise ValueError("DNS server is already running")
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.listen_address, self.listen_port))
            self.running = True
            
            self.thread = threading.Thread(target=self._listen_loop)
            self.thread.daemon = True
            self.thread.start()
            
            print(f"[DNS] DNS server started on {self.listen_address}:{self.listen_port}")
            print(f"[DNS] Responding to all queries with IP: {self.response_ip}")
            
        except Exception as e:
            print(f"[DNS ERROR] Failed to start DNS server: {e}")
            if self.socket:
                self.socket.close()
            raise
    
    def stop(self):
        """Stop the DNS server"""
        if self.running:
            self.running = False
            if self.socket:
                self.socket.close()
            if self.thread:
                self.thread.join(timeout=2)
            print("[DNS] DNS server stopped")
    
    def _listen_loop(self):
        """Main listening loop for DNS queries"""
        while self.running:
            try:
                data, addr = self.socket.recvfrom(512)
                if data:
                    response = self._process_query(data, addr)
                    if response:
                        self.socket.sendto(response, addr)
            except socket.error:
                if self.running:  # Only print error if we're supposed to be running
                    print("[DNS ERROR] Socket error in DNS server")
                break
            except Exception as e:
                if self.running:
                    print(f"[DNS ERROR] Error processing DNS query: {e}")
    
    def _process_query(self, data, addr):
        """Process a DNS query and return a response"""
        try:
            # Parse the DNS query
            query_domain = self._parse_query(data)
            
            if self.print_queries:
                print(f"[DNS] Query from {addr[0]}: {query_domain}")
            
            # Create DNS response
            response = self._create_response(data, query_domain)
            return response
            
        except Exception as e:
            if self.print_queries:
                print(f"[DNS ERROR] Failed to process query from {addr[0]}: {e}")
            return None
    
    def _parse_query(self, data):
        """Parse DNS query to extract the domain name"""
        if len(data) < 12:
            return "invalid"
        
        # Skip DNS header (12 bytes)
        pos = 12
        domain_parts = []
        
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            if pos + length > len(data):
                break
            domain_parts.append(data[pos:pos + length].decode('utf-8', errors='ignore'))
            pos += length
        
        return '.'.join(domain_parts) if domain_parts else "unknown"
    
    def _create_response(self, query_data, domain):
        """Create a DNS response packet"""
        if len(query_data) < 12:
            return None
        
        # Extract transaction ID from query
        transaction_id = query_data[0:2]
        
        # DNS Header for response
        # Flags: 0x8180 (response, recursion available)
        flags = struct.pack('>H', 0x8180)
        questions = struct.pack('>H', 1)  # 1 question
        answers = struct.pack('>H', 1)    # 1 answer
        authority = struct.pack('>H', 0)  # 0 authority records
        additional = struct.pack('>H', 0) # 0 additional records
        
        # Build header
        header = transaction_id + flags + questions + answers + authority + additional
        
        # Question section (copy from original query)
        question_start = 12
        question_end = question_start
        
        # Find end of question section
        while question_end < len(query_data):
            length = query_data[question_end]
            if length == 0:
                question_end += 5  # null byte + qtype (2) + qclass (2)
                break
            question_end += length + 1
        
        question_section = query_data[question_start:question_end]
        
        # Answer section
        # Name pointer to question (0xC00C points to offset 12)
        name_pointer = struct.pack('>H', 0xC00C)
        
        # Type A record (1), Class IN (1)
        rr_type = struct.pack('>H', 1)
        rr_class = struct.pack('>H', 1)
        
        # TTL (300 seconds)
        ttl = struct.pack('>I', 300)
        
        # Data length (4 bytes for IPv4)
        data_length = struct.pack('>H', 4)
        
        # IP address
        ip_parts = self.response_ip.split('.')
        ip_bytes = struct.pack('BBBB', int(ip_parts[0]), int(ip_parts[1]), 
                              int(ip_parts[2]), int(ip_parts[3]))
        
        answer_section = name_pointer + rr_type + rr_class + ttl + data_length + ip_bytes
        
        return header + question_section + answer_section
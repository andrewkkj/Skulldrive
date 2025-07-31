#!/usr/bin/env python3
"""
Analisador de Alvo
Análise automática para determinar melhor protocolo e vulnerabilidades
"""

import socket
import time
import threading
import nmap
from scapy.all import *
from colorama import Fore, Style

class TargetAnalyzer:
    """Analisador automático de alvos"""
    
    def __init__(self, target, port=80):
        self.target = target
        self.port = port
        self.results = {}
        
    def analyze(self):
        """Executa análise completa do alvo"""
        print(f"{Fore.CYAN}[*] Iniciando análise do alvo: {self.target}:{self.port}{Style.RESET_ALL}")
        
        # Análises básicas
        self._analyze_connectivity()
        self._analyze_ports()
        self._analyze_protocols()
        self._analyze_response_times()
        self._analyze_vulnerabilities()
        
        # Gerar relatório
        self._generate_report()
        
        return self.results
    
    def _analyze_connectivity(self):
        """Análise de conectividade básica"""
        print(f"{Fore.YELLOW}[*] Analisando conectividade{Style.RESET_ALL}")
        
        try:
            # Resolução DNS
            ip = socket.gethostbyname(self.target)
            self.results['ip'] = ip
            print(f"{Fore.GREEN}[+] IP resolvido: {ip}{Style.RESET_ALL}")
            
            # Ping básico
            ping_result = self._ping_test(ip)
            self.results['ping'] = ping_result
            print(f"{Fore.GREEN}[+] Ping: {ping_result['avg_time']:.2f}ms{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Erro na análise de conectividade: {e}{Style.RESET_ALL}")
    
    def _ping_test(self, ip, count=5):
        """Teste de ping"""
        times = []
        
        for i in range(count):
            try:
                start_time = time.time()
                response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=False)
                if response:
                    end_time = time.time()
                    times.append((end_time - start_time) * 1000)
            except:
                pass
        
        if times:
            return {
                'avg_time': sum(times) / len(times),
                'min_time': min(times),
                'max_time': max(times),
                'packet_loss': (count - len(times)) / count * 100
            }
        else:
            return {'avg_time': 0, 'min_time': 0, 'max_time': 0, 'packet_loss': 100}
    
    def _analyze_ports(self):
        """Análise de portas abertas"""
        print(f"{Fore.YELLOW}[*] Analisando portas{Style.RESET_ALL}")
        
        try:
            nm = nmap.PortScanner()
            
            # Scan das portas mais comuns
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080]
            
            for port in common_ports:
                try:
                    result = nm.scan(self.target, str(port))
                    if self.target in result['scan']:
                        state = result['scan'][self.target]['tcp'][port]['state']
                        if state == 'open':
                            print(f"{Fore.GREEN}[+] Porta {port} está aberta{Style.RESET_ALL}")
                except:
                    pass
            
            self.results['open_ports'] = [port for port in common_ports 
                                        if self._is_port_open(port)]
            
        except Exception as e:
            print(f"{Fore.RED}[!] Erro na análise de portas: {e}{Style.RESET_ALL}")
    
    def _is_port_open(self, port):
        """Verifica se uma porta está aberta"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _analyze_protocols(self):
        """Análise de protocolos e respostas"""
        print(f"{Fore.YELLOW}[*] Analisando protocolos{Style.RESET_ALL}")
        
        protocols = {
            'http': 80,
            'https': 443,
            'ftp': 21,
            'ssh': 22,
            'smtp': 25,
            'dns': 53
        }
        
        protocol_results = {}
        
        for protocol, port in protocols.items():
            if self._is_port_open(port):
                response = self._test_protocol(protocol, port)
                protocol_results[protocol] = response
                print(f"{Fore.GREEN}[+] {protocol.upper()}: {response['status']}{Style.RESET_ALL}")
        
        self.results['protocols'] = protocol_results
    
    def _test_protocol(self, protocol, port):
        """Testa um protocolo específico"""
        try:
            if protocol == 'http':
                return self._test_http(port)
            elif protocol == 'https':
                return self._test_https(port)
            elif protocol == 'ssh':
                return self._test_ssh(port)
            else:
                return {'status': 'open', 'response_time': 0}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _test_http(self, port):
        """Testa protocolo HTTP"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            # Enviar requisição HTTP básica
            request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            sock.send(request.encode())
            
            # Receber resposta
            response = sock.recv(1024).decode()
            sock.close()
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            return {
                'status': 'open',
                'response_time': response_time,
                'server': self._extract_server_header(response)
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _test_https(self, port):
        """Testa protocolo HTTPS"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            # Enviar requisição HTTPS básica
            request = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
            sock.send(request.encode())
            
            # Receber resposta
            response = sock.recv(1024).decode()
            sock.close()
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            return {
                'status': 'open',
                'response_time': response_time,
                'server': self._extract_server_header(response)
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _test_ssh(self, port):
        """Testa protocolo SSH"""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, port))
            
            # Receber banner SSH
            banner = sock.recv(1024).decode()
            sock.close()
            
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            return {
                'status': 'open',
                'response_time': response_time,
                'banner': banner.strip()
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _extract_server_header(self, response):
        """Extrai header Server da resposta HTTP"""
        lines = response.split('\r\n')
        for line in lines:
            if line.lower().startswith('server:'):
                return line.split(':', 1)[1].strip()
        return 'Unknown'
    
    def _analyze_response_times(self):
        """Análise de tempos de resposta"""
        print(f"{Fore.YELLOW}[*] Analisando tempos de resposta{Style.RESET_ALL}")
        
        response_times = {}
        
        # Testar diferentes tipos de requisição
        test_requests = [
            ('GET', '/'),
            ('GET', '/index.html'),
            ('HEAD', '/'),
            ('POST', '/')
        ]
        
        for method, path in test_requests:
            times = []
            for _ in range(5):
                try:
                    start_time = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.target, self.port))
                    
                    request = f"{method} {path} HTTP/1.1\r\nHost: {self.target}\r\n\r\n"
                    sock.send(request.encode())
                    
                    response = sock.recv(1024)
                    sock.close()
                    
                    end_time = time.time()
                    times.append((end_time - start_time) * 1000)
                    
                except Exception as e:
                    pass
            
            if times:
                response_times[f"{method}_{path}"] = {
                    'avg_time': sum(times) / len(times),
                    'min_time': min(times),
                    'max_time': max(times)
                }
        
        self.results['response_times'] = response_times
    
    def _analyze_vulnerabilities(self):
        """Análise de vulnerabilidades básicas"""
        print(f"{Fore.YELLOW}[*] Analisando vulnerabilidades{Style.RESET_ALL}")
        
        vulnerabilities = []
        
        # Testar vulnerabilidades comuns
        vuln_tests = [
            ('slow_headers', self._test_slow_headers),
            ('connection_limit', self._test_connection_limit),
            ('timeout_behavior', self._test_timeout_behavior)
        ]
        
        for vuln_name, test_func in vuln_tests:
            try:
                result = test_func()
                if result['vulnerable']:
                    vulnerabilities.append({
                        'name': vuln_name,
                        'description': result['description'],
                        'severity': result['severity']
                    })
                    print(f"{Fore.RED}[!] Vulnerabilidade encontrada: {vuln_name}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[*] Erro ao testar {vuln_name}: {e}{Style.RESET_ALL}")
        
        self.results['vulnerabilities'] = vulnerabilities
    
    def _test_slow_headers(self):
        """Testa vulnerabilidade a headers lentos"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((self.target, self.port))
            
            # Enviar headers muito lentamente
            headers = [
                "GET / HTTP/1.1\r\n",
                f"Host: {self.target}\r\n",
                "User-Agent: Mozilla/5.0\r\n"
            ]
            
            for header in headers:
                sock.send(header.encode())
                time.sleep(15)  # Delay muito longo
            
            # Se chegou até aqui, pode ser vulnerável
            sock.close()
            return {
                'vulnerable': True,
                'description': 'Servidor aceita headers muito lentos',
                'severity': 'medium'
            }
        except:
            return {'vulnerable': False}
    
    def _test_connection_limit(self):
        """Testa limite de conexões simultâneas"""
        try:
            sockets = []
            max_connections = 0
            
            # Tentar criar conexões até falhar
            for i in range(100):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target, self.port))
                    sockets.append(sock)
                    max_connections = i + 1
                except:
                    break
            
            # Fechar conexões
            for sock in sockets:
                sock.close()
            
            if max_connections < 50:
                return {
                    'vulnerable': True,
                    'description': f'Limite baixo de conexões: {max_connections}',
                    'severity': 'high'
                }
            else:
                return {'vulnerable': False}
                
        except Exception as e:
            return {'vulnerable': False}
    
    def _test_timeout_behavior(self):
        """Testa comportamento de timeout"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            sock.connect((self.target, self.port))
            
            # Enviar dados e não fechar
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            
            # Aguardar resposta
            start_time = time.time()
            response = sock.recv(1024)
            response_time = time.time() - start_time
            
            sock.close()
            
            if response_time > 10:
                return {
                    'vulnerable': True,
                    'description': f'Timeout lento: {response_time:.2f}s',
                    'severity': 'low'
                }
            else:
                return {'vulnerable': False}
                
        except Exception as e:
            return {'vulnerable': False}
    
    def _generate_report(self):
        """Gera relatório final da análise"""
        print(f"{Fore.CYAN}[*] Gerando relatório de análise{Style.RESET_ALL}")
        
        report = {
            'target': self.target,
            'port': self.port,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': self._generate_summary(),
            'recommendations': self._generate_recommendations()
        }
        
        self.results['report'] = report
        
        # Exibir resumo
        print(f"\n{Fore.GREEN}=== RELATÓRIO DE ANÁLISE ==={Style.RESET_ALL}")
        print(f"Alvo: {self.target}:{self.port}")
        print(f"IP: {self.results.get('ip', 'N/A')}")
        print(f"Ping médio: {self.results.get('ping', {}).get('avg_time', 0):.2f}ms")
        print(f"Portas abertas: {len(self.results.get('open_ports', []))}")
        print(f"Vulnerabilidades: {len(self.results.get('vulnerabilities', []))}")
        
        if self.results.get('vulnerabilities'):
            print(f"\n{Fore.RED}Vulnerabilidades encontradas:{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                print(f"  - {vuln['name']}: {vuln['description']} ({vuln['severity']})")
    
    def _generate_summary(self):
        """Gera resumo da análise"""
        summary = {
            'connectivity': 'good' if self.results.get('ping', {}).get('packet_loss', 100) < 10 else 'poor',
            'open_ports': len(self.results.get('open_ports', [])),
            'vulnerabilities': len(self.results.get('vulnerabilities', [])),
            'best_protocol': self._determine_best_protocol()
        }
        return summary
    
    def _determine_best_protocol(self):
        """Determina o melhor protocolo para ataque"""
        protocols = self.results.get('protocols', {})
        
        if not protocols:
            return 'unknown'
        
        # Priorizar protocolos comuns
        priority_order = ['http', 'https', 'ssh', 'ftp', 'smtp']
        
        for protocol in priority_order:
            if protocol in protocols and protocols[protocol]['status'] == 'open':
                return protocol
        
        # Se nenhum dos prioritários, retornar o primeiro disponível
        for protocol, data in protocols.items():
            if data['status'] == 'open':
                return protocol
        
        return 'unknown'
    
    def _generate_recommendations(self):
        """Gera recomendações baseadas na análise"""
        recommendations = []
        
        # Recomendações baseadas em vulnerabilidades
        vulnerabilities = self.results.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if vuln['name'] == 'slow_headers':
                recommendations.append("Servidor vulnerável a ataques Slowloris - use modo slow")
            elif vuln['name'] == 'connection_limit':
                recommendations.append("Limite baixo de conexões - use modo saturation")
            elif vuln['name'] == 'timeout_behavior':
                recommendations.append("Timeout lento - use modo exploit com slow_headers")
        
        # Recomendações baseadas em protocolos
        best_protocol = self._determine_best_protocol()
        if best_protocol == 'http':
            recommendations.append("HTTP disponível - ideal para ataques web")
        elif best_protocol == 'ssh':
            recommendations.append("SSH disponível - considere ataques de força bruta")
        
        # Recomendações baseadas em conectividade
        ping_data = self.results.get('ping', {})
        if ping_data.get('packet_loss', 0) > 50:
            recommendations.append("Alta perda de pacotes - considere ataques UDP")
        
        return recommendations 
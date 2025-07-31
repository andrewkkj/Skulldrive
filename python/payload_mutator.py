#!/usr/bin/env python3
"""
Mutador de Payloads
Mutação automática para tornar ataques mais difíceis de detectar
"""

import random
import string
import base64
import hashlib
import time
from cryptography.fernet import Fernet

class PayloadMutator:
    """Mutador automático de payloads"""
    
    def __init__(self):
        self.mutation_count = 0
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        
        # Padrões de mutação
        self.mutation_patterns = [
            self._add_random_chars,
            self._encode_base64,
            self._add_encryption,
            self._add_compression,
            self._add_obfuscation,
            self._add_polymorphism
        ]
    
    def mutate_syn_payload(self):
        """Mutação de payload SYN"""
        base_payload = self._generate_base_syn_payload()
        return self._apply_mutations(base_payload)
    
    def mutate_http_payload(self):
        """Mutação de payload HTTP"""
        base_payload = self._generate_base_http_payload()
        return self._apply_mutations(base_payload)
    
    def mutate_udp_payload(self):
        """Mutação de payload UDP"""
        base_payload = self._generate_base_udp_payload()
        return self._apply_mutations(base_payload)
    
    def _generate_base_syn_payload(self):
        """Gera payload SYN base"""
        payloads = [
            b"SYN_REQUEST",
            b"CONNECTION_INIT",
            b"TCP_HANDSHAKE",
            b"SESSION_START"
        ]
        return random.choice(payloads)
    
    def _generate_base_http_payload(self):
        """Gera payload HTTP base"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15"
        ]
        
        headers = [
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "Connection: keep-alive",
            "Upgrade-Insecure-Requests: 1"
        ]
        
        payload = f"GET / HTTP/1.1\r\n"
        payload += f"Host: target\r\n"
        payload += f"User-Agent: {random.choice(user_agents)}\r\n"
        payload += f"{random.choice(headers)}\r\n"
        payload += "\r\n"
        
        return payload.encode()
    
    def _generate_base_udp_payload(self):
        """Gera payload UDP base"""
        payloads = [
            b"UDP_DATAGRAM",
            b"UDP_PACKET",
            b"UDP_MESSAGE",
            b"UDP_DATA"
        ]
        return random.choice(payloads)
    
    def _apply_mutations(self, payload):
        """Aplica mutações ao payload"""
        self.mutation_count += 1
        
        # Escolher padrões de mutação aleatoriamente
        num_mutations = random.randint(1, 3)
        selected_patterns = random.sample(self.mutation_patterns, num_mutations)
        
        mutated_payload = payload
        
        for pattern in selected_patterns:
            mutated_payload = pattern(mutated_payload)
        
        return mutated_payload
    
    def _add_random_chars(self, payload):
        """Adiciona caracteres aleatórios"""
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', errors='ignore')
        
        # Adicionar caracteres aleatórios no início e fim
        prefix = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 15)))
        suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 15)))
        
        return (prefix + payload + suffix).encode()
    
    def _encode_base64(self, payload):
        """Codifica payload em base64"""
        if isinstance(payload, str):
            payload = payload.encode()
        
        encoded = base64.b64encode(payload)
        return encoded
    
    def _add_encryption(self, payload):
        """Adiciona criptografia simples"""
        if isinstance(payload, str):
            payload = payload.encode()
        
        # Criptografia simples com XOR
        key = random.randint(1, 255)
        encrypted = bytes([b ^ key for b in payload])
        
        # Adicionar chave no início
        return bytes([key]) + encrypted
    
    def _add_compression(self, payload):
        """Simula compressão (adiciona marcadores)"""
        if isinstance(payload, str):
            payload = payload.encode()
        
        # Adicionar marcadores de compressão
        compressed = b"COMPRESSED:" + payload + b":END"
        return compressed
    
    def _add_obfuscation(self, payload):
        """Adiciona ofuscação"""
        if isinstance(payload, str):
            payload = payload.encode()
        
        # Ofuscação simples com substituição
        obfuscated = payload.replace(b'a', b'@').replace(b'e', b'3').replace(b'i', b'1')
        return obfuscated
    
    def _add_polymorphism(self, payload):
        """Adiciona polimorfismo"""
        if isinstance(payload, str):
            payload = payload.encode()
        
        # Adicionar timestamp para polimorfismo
        timestamp = str(int(time.time())).encode()
        polymorphic = timestamp + b":" + payload + b":" + timestamp
        
        return polymorphic
    
    def mutate_headers(self, headers):
        """Mutação de headers HTTP"""
        mutated_headers = {}
        
        for key, value in headers.items():
            # Mutar chave
            mutated_key = self._mutate_string(key)
            
            # Mutar valor
            mutated_value = self._mutate_string(value)
            
            mutated_headers[mutated_key] = mutated_value
        
        return mutated_headers
    
    def _mutate_string(self, text):
        """Mutação de string"""
        if not isinstance(text, str):
            return text
        
        mutations = [
            lambda s: s.upper(),
            lambda s: s.lower(),
            lambda s: s.replace('a', '@').replace('e', '3').replace('i', '1'),
            lambda s: ''.join(random.choices(string.ascii_letters, k=len(s))),
            lambda s: base64.b64encode(s.encode()).decode()
        ]
        
        # Aplicar mutação aleatória
        mutation = random.choice(mutations)
        return mutation(text)
    
    def generate_polymorphic_signature(self):
        """Gera assinatura polimórfica"""
        timestamp = int(time.time())
        random_data = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        
        signature = f"{timestamp}:{random_data}:{self.mutation_count}"
        return hashlib.md5(signature.encode()).hexdigest()
    
    def get_mutation_stats(self):
        """Retorna estatísticas de mutação"""
        return {
            'total_mutations': self.mutation_count,
            'current_signature': self.generate_polymorphic_signature(),
            'encryption_key': self.key.decode() if self.key else None
        } 
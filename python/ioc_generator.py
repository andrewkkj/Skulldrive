#!/usr/bin/env python3
"""
Gerador de IoC (Indicators of Compromise)
Gera artefatos visíveis em logs de IDS
"""

import json
import time
import random
import hashlib
import base64
from datetime import datetime, timedelta
from colorama import Fore, Style

class IoCGenerator:
    """Gerador de IoC customizados"""
    
    def __init__(self):
        self.ioc_types = {
            'ip': [],
            'domain': [],
            'url': [],
            'hash': [],
            'email': [],
            'registry': [],
            'file': []
        }
        self.campaign_id = self._generate_campaign_id()
    
    def _generate_campaign_id(self):
        """Gera ID único da campanha"""
        timestamp = int(time.time())
        random_suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=6))
        return f"ENGINE_{timestamp}_{random_suffix}"
    
    def generate_ioc(self, target, attack_mode):
        """Gera IoC baseado no alvo e modo de ataque"""
        print(f"{Fore.CYAN}[*] Gerando IoC para {target} ({attack_mode}){Style.RESET_ALL}")
        
        # Gerar IoC baseado no modo
        if attack_mode == "slow":
            self._generate_slow_ioc(target)
        elif attack_mode == "saturation":
            self._generate_saturation_ioc(target)
        elif attack_mode == "exploit":
            self._generate_exploit_ioc(target)
        else:
            self._generate_generic_ioc(target)
        
        # Gerar relatório
        report = self._generate_ioc_report(target, attack_mode)
        
        # Salvar IoC
        self._save_ioc_report(report)
        
        return report
    
    def _generate_slow_ioc(self, target):
        """Gera IoC para ataques slow"""
        print(f"{Fore.YELLOW}[*] Gerando IoC para ataques Slow-and-Slow{Style.RESET_ALL}")
        
        # IPs de origem (simulando botnet)
        for _ in range(5):
            ip = self._generate_random_ip()
            self.ioc_types['ip'].append({
                'value': ip,
                'type': 'source_ip',
                'description': 'IP de origem para ataque Slowloris',
                'confidence': random.randint(70, 95)
            })
        
        # Domínios C&C
        for _ in range(3):
            domain = self._generate_random_domain()
            self.ioc_types['domain'].append({
                'value': domain,
                'type': 'c2_domain',
                'description': 'Domínio C&C para controle de botnet',
                'confidence': random.randint(80, 95)
            })
        
        # URLs de controle
        for _ in range(2):
            url = f"http://{self._generate_random_domain()}/control.php"
            self.ioc_types['url'].append({
                'value': url,
                'type': 'c2_url',
                'description': 'URL de controle da botnet',
                'confidence': random.randint(75, 90)
            })
        
        # Hashes de malware
        for _ in range(3):
            hash_value = self._generate_random_hash()
            self.ioc_types['hash'].append({
                'value': hash_value,
                'type': 'malware_hash',
                'description': 'Hash de malware para ataque Slowloris',
                'confidence': random.randint(85, 95)
            })
    
    def _generate_saturation_ioc(self, target):
        """Gera IoC para ataques de saturação"""
        print(f"{Fore.YELLOW}[*] Gerando IoC para ataques de Saturação{Style.RESET_ALL}")
        
        # IPs de origem (simulando DDoS)
        for _ in range(10):
            ip = self._generate_random_ip()
            self.ioc_types['ip'].append({
                'value': ip,
                'type': 'ddos_source',
                'description': 'IP de origem para ataque DDoS',
                'confidence': random.randint(75, 90)
            })
        
        # Domínios de amplificação
        for _ in range(5):
            domain = self._generate_random_domain()
            self.ioc_types['domain'].append({
                'value': domain,
                'type': 'amplification_domain',
                'description': 'Domínio usado para amplificação DDoS',
                'confidence': random.randint(70, 85)
            })
        
        # Arquivos de configuração
        for _ in range(2):
            filename = f"ddos_config_{random.randint(1000, 9999)}.txt"
            self.ioc_types['file'].append({
                'value': filename,
                'type': 'ddos_config',
                'description': 'Arquivo de configuração DDoS',
                'confidence': random.randint(80, 90)
            })
    
    def _generate_exploit_ioc(self, target):
        """Gera IoC para ataques de exploração"""
        print(f"{Fore.YELLOW}[*] Gerando IoC para ataques de Exploração{Style.RESET_ALL}")
        
        # IPs de origem
        for _ in range(3):
            ip = self._generate_random_ip()
            self.ioc_types['ip'].append({
                'value': ip,
                'type': 'exploit_source',
                'description': 'IP de origem para exploração',
                'confidence': random.randint(80, 95)
            })
        
        # URLs de exploração
        for _ in range(4):
            url = f"http://{self._generate_random_domain()}/exploit.php"
            self.ioc_types['url'].append({
                'value': url,
                'description': 'URL de exploração',
                'confidence': random.randint(85, 95)
            })
        
        # Emails de phishing
        for _ in range(2):
            email = f"admin@{self._generate_random_domain()}"
            self.ioc_types['email'].append({
                'value': email,
                'type': 'phishing_email',
                'description': 'Email usado em phishing',
                'confidence': random.randint(75, 90)
            })
        
        # Registros do Windows
        registry_keys = [
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
        ]
        
        for key in registry_keys:
            self.ioc_types['registry'].append({
                'value': key,
                'type': 'persistence_registry',
                'description': 'Registro para persistência',
                'confidence': random.randint(80, 95)
            })
    
    def _generate_generic_ioc(self, target):
        """Gera IoC genérico"""
        print(f"{Fore.YELLOW}[*] Gerando IoC genérico{Style.RESET_ALL}")
        
        # IPs básicos
        for _ in range(3):
            ip = self._generate_random_ip()
            self.ioc_types['ip'].append({
                'value': ip,
                'type': 'malicious_ip',
                'description': 'IP malicioso',
                'confidence': random.randint(70, 85)
            })
        
        # Domínios básicos
        for _ in range(2):
            domain = self._generate_random_domain()
            self.ioc_types['domain'].append({
                'value': domain,
                'type': 'malicious_domain',
                'description': 'Domínio malicioso',
                'confidence': random.randint(75, 90)
            })
    
    def _generate_random_ip(self):
        """Gera IP aleatório"""
        return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    def _generate_random_domain(self):
        """Gera domínio aleatório"""
        tlds = ['com', 'net', 'org', 'info', 'biz', 'co', 'io']
        domains = ['malware', 'botnet', 'c2', 'control', 'server', 'host', 'node']
        
        domain = random.choice(domains)
        tld = random.choice(tlds)
        subdomain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(3, 8)))
        
        return f"{subdomain}.{domain}.{tld}"
    
    def _generate_random_hash(self):
        """Gera hash aleatório"""
        data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=32))
        return hashlib.md5(data.encode()).hexdigest()
    
    def _generate_ioc_report(self, target, attack_mode):
        """Gera relatório de IoC"""
        timestamp = datetime.now().isoformat()
        
        report = {
            'campaign_id': self.campaign_id,
            'target': target,
            'attack_mode': attack_mode,
            'timestamp': timestamp,
            'ioc_count': sum(len(iocs) for iocs in self.ioc_types.values()),
            'iocs': self.ioc_types,
            'metadata': {
                'generator': 'Engine de Ataque',
                'version': '1.0',
                'confidence_threshold': 70
            }
        }
        
        return report
    
    def _save_ioc_report(self, report):
        """Salva relatório de IoC"""
        filename = f"ioc_report_{self.campaign_id}_{int(time.time())}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"{Fore.GREEN}[+] IoC salvo em: {filename}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao salvar IoC: {e}{Style.RESET_ALL}")
    
    def generate_stix_ioc(self, report):
        """Gera IoC no formato STIX"""
        stix_objects = []
        
        for ioc_type, iocs in report['iocs'].items():
            for ioc in iocs:
                stix_object = {
                    'type': 'indicator',
                    'id': f"indicator--{hashlib.md5(ioc['value'].encode()).hexdigest()}",
                    'created': datetime.now().isoformat(),
                    'modified': datetime.now().isoformat(),
                    'pattern': f"[{ioc_type}:value = '{ioc['value']}']",
                    'valid_from': datetime.now().isoformat(),
                    'labels': [ioc['type'], 'malicious'],
                    'confidence': ioc['confidence'] / 100
                }
                stix_objects.append(stix_object)
        
        stix_bundle = {
            'type': 'bundle',
            'id': f"bundle--{self.campaign_id}",
            'objects': stix_objects
        }
        
        return stix_bundle
    
    def generate_sigma_rule(self, report):
        """Gera regra Sigma baseada nos IoC"""
        sigma_rule = {
            'title': f"Engine de Ataque - {report['attack_mode']}",
            'id': f"engine-attack-{report['attack_mode']}-{self.campaign_id}",
            'description': f"Detecta atividade da Engine de Ataque em modo {report['attack_mode']}",
            'author': 'Engine de Ataque',
            'date': datetime.now().strftime('%Y/%m/%d'),
            'logsource': {
                'category': 'network_traffic',
                'product': 'windows'
            },
            'detection': {
                'selection': {},
                'condition': 'selection'
            },
            'level': 'high'
        }
        
        # Adicionar condições baseadas nos IoC
        if report['iocs']['ip']:
            ips = [ioc['value'] for ioc in report['iocs']['ip']]
            sigma_rule['detection']['selection']['src_ip'] = ips
        
        if report['iocs']['domain']:
            domains = [ioc['value'] for ioc in report['iocs']['domain']]
            sigma_rule['detection']['selection']['dst_hostname'] = domains
        
        return sigma_rule
    
    def generate_yara_rule(self, report):
        """Gera regra YARA baseada nos IoC"""
        yara_rule = f"""
rule EngineAttack_{report['attack_mode'].upper()}_{self.campaign_id}
{{
    meta:
        description = "Engine de Ataque - {report['attack_mode']}"
        author = "Engine de Ataque"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        campaign_id = "{self.campaign_id}"
    
    strings:
"""
        
        # Adicionar strings baseadas nos IoC
        for ioc_type, iocs in report['iocs'].items():
            for ioc in iocs:
                if ioc_type in ['domain', 'url', 'email']:
                    yara_rule += f'        $s{ioc_type} = "{ioc["value"]}"\n'
        
        yara_rule += """
    condition:
        any of them
}
"""
        
        return yara_rule
    
    def print_ioc_summary(self, report):
        """Exibe resumo dos IoC gerados"""
        print(f"\n{Fore.GREEN}=== RESUMO DE IOC ==={Style.RESET_ALL}")
        print(f"Campanha ID: {report['campaign_id']}")
        print(f"Alvo: {report['target']}")
        print(f"Modo: {report['attack_mode']}")
        print(f"Total de IoC: {report['ioc_count']}")
        
        for ioc_type, iocs in report['iocs'].items():
            if iocs:
                print(f"\n{ioc_type.upper()}:")
                for ioc in iocs:
                    print(f"  - {ioc['value']} ({ioc['confidence']}% confiança)")
                    print(f"    {ioc['description']}")
    
    def export_ioc_formats(self, report):
        """Exporta IoC em diferentes formatos"""
        print(f"{Fore.CYAN}[*] Exportando IoC em diferentes formatos{Style.RESET_ALL}")
        
        # STIX
        stix_data = self.generate_stix_ioc(report)
        stix_filename = f"stix_{self.campaign_id}.json"
        with open(stix_filename, 'w') as f:
            json.dump(stix_data, f, indent=2)
        print(f"{Fore.GREEN}[+] STIX salvo em: {stix_filename}{Style.RESET_ALL}")
        
        # Sigma
        sigma_rule = self.generate_sigma_rule(report)
        sigma_filename = f"sigma_{self.campaign_id}.yml"
        import yaml
        with open(sigma_filename, 'w') as f:
            yaml.dump(sigma_rule, f, default_flow_style=False)
        print(f"{Fore.GREEN}[+] Sigma salvo em: {sigma_filename}{Style.RESET_ALL}")
        
        # YARA
        yara_rule = self.generate_yara_rule(report)
        yara_filename = f"yara_{self.campaign_id}.yar"
        with open(yara_filename, 'w') as f:
            f.write(yara_rule)
        print(f"{Fore.GREEN}[+] YARA salvo em: {yara_filename}{Style.RESET_ALL}") 
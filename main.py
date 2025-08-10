#!/usr/bin/env python3
"""
Engine de Ataque de Baixo e Alto Volume
Interface CLI principal
"""

import argparse
import sys
import time
from colorama import init, Fore, Style
from python.engine import AttackEngine
from python.analyzer import TargetAnalyzer
from python.ioc_generator import IoCGenerator

init(autoreset=True)

def print_banner():
    """Exibe o banner da engine"""
    banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║                    ENGINE DE ATAQUE                                    ║
║              Baixo e Alto Volume + Stealth                            ║
║                                                                        ║
║  [Low-and-Slow] [Saturação] [Exploração] [IoC]                      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def parse_arguments():
    """Parse dos argumentos da linha de comando"""
    parser = argparse.ArgumentParser(
        description="Engine de Ataque de Baixo e Alto Volume",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
    python3 main.py --mode slow --target example.com --port 80
    python3 main.py --mode saturation --target example.com --duration 60
    python3 main.py --mode exploit --target example.com --vulnerability tcp_reuse
        """
    )
    
    parser.add_argument("--mode", required=True, 
                        choices=["slow", "saturation", "exploit", "analyze"],
                        help="Modo de operação")
    
    parser.add_argument("--target", required=True,
                        help="Alvo (IP ou domínio)")
    
    parser.add_argument("--port", type=int, default=80,
                        help="Porta do alvo (padrão: 80)")
    
    parser.add_argument("--duration", type=int, default=30,
                        help="Duração em segundos (padrão: 30)")
    
    parser.add_argument("--threads", type=int, default=10,
                        help="Número de threads (padrão: 10)")
    
    parser.add_argument("--stealth", action="store_true",
                        help="Ativar modo stealth")
    
    parser.add_argument("--vulnerability", 
                        choices=["tcp_reuse", "slow_headers", "connection_flood"],
                        help="Vulnerabilidade específica para explorar")
    
    parser.add_argument("--ioc", action="store_true",
                        help="Gerar IoC customizados")
    
    parser.add_argument("--payload-mutation", action="store_true",
                        help="Ativar mutação automática de payloads")
    
    return parser.parse_args()

def main():
    """Função principal"""
    print_banner()
    
    try:
        args = parse_arguments()
        
        print(f"{Fore.CYAN}[*] Iniciando Engine de Ataque{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Alvo: {args.target}:{args.port}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Modo: {args.mode}{Style.RESET_ALL}")
        
        # Análise do alvo se solicitado
        if args.mode == "analyze":
            analyzer = TargetAnalyzer(args.target, args.port)
            results = analyzer.analyze()
            print(f"{Fore.GREEN}[+] Análise concluída{Style.RESET_ALL}")
            return
        
        # Inicializar engine
        engine = AttackEngine(
            target=args.target,
            port=args.port,
            duration=args.duration,
            threads=args.threads,
            stealth=args.stealth,
            payload_mutation=args.payload_mutation
        )
        
        # Executar ataque baseado no modo
        if args.mode == "slow":
            print(f"{Fore.BLUE}[*] Executando ataque Low-and-Slow{Style.RESET_ALL}")
            engine.low_and_slow_attack()
            
        elif args.mode == "saturation":
            print(f"{Fore.BLUE}[*] Executando ataque de Saturação{Style.RESET_ALL}")
            engine.saturation_attack()
            
        elif args.mode == "exploit":
            if not args.vulnerability:
                print(f"{Fore.RED}[!] Vulnerabilidade deve ser especificada para modo exploit{Style.RESET_ALL}")
                sys.exit(1)
            print(f"{Fore.BLUE}[*] Executando exploração: {args.vulnerability}{Style.RESET_ALL}")
            engine.exploit_attack(args.vulnerability)
        
        # Gerar IoC se solicitado
        if args.ioc:
            print(f"{Fore.CYAN}[*] Gerando IoC customizados{Style.RESET_ALL}")
            ioc_gen = IoCGenerator()
            ioc_gen.generate_ioc(args.target, args.mode)
        
        print(f"{Fore.GREEN}[+] Ataque concluído{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrompido pelo usuário{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
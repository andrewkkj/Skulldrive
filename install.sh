#!/bin/bash

# ===============================
#  Script de Instalação da Engine de Ataque
#  Engine de Ataque - Baixo/Alto Volume + Stealth
# ===============================

set -euo pipefail

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções utilitárias de impressão
log()    { echo -e "${BLUE}[*]${NC} $1"; }
success(){ echo -e "${GREEN}[+]${NC} $1"; }
warn()   { echo -e "${YELLOW}[!]${NC} $1"; }
error()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# Banner
clear
echo -e "${BLUE}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                      ENGINE DE ATAQUE                        ║
║              Baixo e Alto Volume + Stealth                   ║
║    [Low-and-Slow] [Saturacao] [Exploracao] [IoC]             ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

log "Iniciando instalação da Engine de Ataque..."

# Verifica se o script está sendo executado como root
if [[ $EUID -eq 0 ]]; then
    warn "Execute este script como um usuário não-root."
    exit 1
fi

# Verifica sistema operacional
log "Verificando sistema operacional..."
case "$OSTYPE" in
    linux*) success "Sistema Linux detectado";;
    darwin*) warn "macOS detectado - pode haver limitações";;
    *) error "Sistema operacional não suportado: $OSTYPE";;
esac

# Dependências de sistema
log "Verificando dependências do sistema..."
SYS_DEPS=(python3 pip3 gcc make git)
MISSING_DEPS=()
for dep in "${SYS_DEPS[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        MISSING_DEPS+=("$dep")
    else
        success "$dep encontrado"
    fi
done

# Instalar dependências ausentes
if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    log "Instalando dependências ausentes: ${MISSING_DEPS[*]}"
    if command -v apt-get &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y "${MISSING_DEPS[@]}"
    elif command -v yum &>/dev/null; then
        sudo yum install -y "${MISSING_DEPS[@]}"
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm "${MISSING_DEPS[@]}"
    else
        error "Gerenciador de pacotes não suportado."
    fi
fi

# Dependências específicas Linux
LINUX_PKGS=(build-essential libpcap-dev python3-dev libssl-dev)
log "Instalando pacotes adicionais do sistema..."
if command -v apt-get &>/dev/null; then
    sudo apt-get install -y "${LINUX_PKGS[@]}"
fi

# Criar estrutura de diretórios
log "Criando estrutura de diretórios..."
dirs=(logs reports ioc/exports payloads/mutations examples config)
for dir in "${dirs[@]}"; do
    mkdir -p "$dir"
done

# Instalar dependências Python
log "Instalando dependências Python..."
if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt
else
    warn "Arquivo requirements.txt não encontrado"
fi

# Compilar core em C
log "Compilando core C..."
if [ -d core ]; then
    pushd core &>/dev/null
    make clean && make
    popd &>/dev/null
else
    error "Diretório core/ não encontrado"
fi

[[ -f core/engine_core ]] && success "Core C compilado com sucesso" || error "Compilação do core C falhou"

# Permissões de arquivos
log "Configurando permissões de execução..."
chmod +x main.py core/engine_core install.sh

# Arquivo de configuração padrão
CONFIG_FILE="config/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    cp config/config.yaml.example "$CONFIG_FILE" 2>/dev/null || warn "Arquivo de configuração padrão já existe"
fi

# Testar instalação
log "Testando instalação..."
python3 -c "import scapy" &>/dev/null && success "Scapy OK" || warn "Scapy não instalado"
python3 -c "import colorama" &>/dev/null && success "Colorama OK" || warn "Colorama não instalado"

# Testar execução do core
log "Testando execução do core..."
./core/engine_core --help &>/dev/null || warn "Core C não respondeu ao --help"

# Criar alias
ALIAS_CMD="alias engine-attack='python3 $(pwd)/main.py'"
if ! grep -q "engine-attack" ~/.bashrc 2>/dev/null; then
    echo "$ALIAS_CMD" >> ~/.bashrc
    success "Alias 'engine-attack' adicionado ao ~/.bashrc"
fi

# Criar logs
log "Criando arquivos de log..."
touch logs/{engine.log,attack.log,stealth.log,ioc.log}

# Exemplo de uso
log "Criando exemplos de uso..."
cat > examples/usage_examples.txt << 'EOF'
# Exemplos de uso da Engine de Ataque

python3 main.py --mode analyze     --target site.com --port 80
python3 main.py --mode slow        --target site.com --port 80 --duration 60 --stealth
python3 main.py --mode saturation  --target site.com --duration 30 --threads 20
python3 main.py --mode exploit     --target site.com --vulnerability tcp_reuse --duration 60
python3 main.py --mode slow        --target site.com --payload-mutation --stealth
python3 main.py --mode slow        --target site.com --ioc --duration 30
engine-attack --mode analyze       --target site.com
EOF
success "Exemplos criados em examples/usage_examples.txt"

# Verifica arquivos principais
FILES=(main.py python/engine.py python/analyzer.py core/engine_core)
for file in "${FILES[@]}"; do
    [[ -f "$file" ]] && success "$file encontrado" || warn "$file não encontrado"
done

# Verifica diretórios
for dir in "${dirs[@]}"; do
    [[ -d "$dir" ]] && success "Diretório $dir OK" || warn "Diretório $dir ausente"
done

# Mensagem final
echo -e "${GREEN}"
cat << "EOF"
╔══════════════════════════════════════════════════════════════╗
║                  INSTALAÇÃO CONCLUÍDA                        ║
║                                                              ║
║  Para iniciar:                                               ║
║    python3 main.py --help                                    ║
║    ou use: engine-attack --help                              ║
║                                                              ║
║  ⚠ Use apenas para testes autorizados                       ║
╚══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

success "Instalação finalizada com sucesso."
log "Reinicie o terminal para ativar o alias 'engine-attack'"
log "Consulte README.md para mais informações."

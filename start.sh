#!/bin/bash

# Home Server Admin - Startup Script
# Inicia o backend Flask e frontend React simultaneamente

set -e

echo "🚀 Starting Home Server Admin..."
echo "=================================="

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função para logging
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Verificar se estamos no diretório correto
if [ ! -f "README.md" ] || [ ! -d "backend" ] || [ ! -d "frontend" ]; then
    error "Please run this script from the home_server_admin directory"
    exit 1
fi

# Verificar dependências do sistema
check_dependencies() {
    log "Checking system dependencies..."
    
    # Python 3
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed"
        exit 1
    fi
    
    # Node.js
    if ! command -v node &> /dev/null; then
        error "Node.js is not installed"
        exit 1
    fi
    
    # pnpm
    if ! command -v pnpm &> /dev/null; then
        warn "pnpm is not installed, trying to install..."
        npm install -g pnpm
    fi
    
    info "All dependencies are available"
}

# Instalar dependências do backend
setup_backend() {
    log "Setting up backend..."
    
    cd backend
    
    # Verificar se requirements.txt existe
    if [ ! -f "requirements.txt" ]; then
        error "requirements.txt not found in backend directory"
        exit 1
    fi
    
    # Instalar dependências Python
    info "Installing Python dependencies..."
    pip install -r requirements.txt
    
    cd ..
    info "Backend setup complete"
}

# Instalar dependências do frontend
setup_frontend() {
    log "Setting up frontend..."
    
    cd frontend/home-server-admin-frontend
    
    # Verificar se package.json existe
    if [ ! -f "package.json" ]; then
        error "package.json not found in frontend directory"
        exit 1
    fi
    
    # Instalar dependências Node.js
    info "Installing Node.js dependencies..."
    pnpm install
    
    cd ../..
    info "Frontend setup complete"
}

# Iniciar backend
start_backend() {
    log "Starting Flask backend..."
    
    cd backend
    
    # Matar processos Flask existentes na porta 5001
    if lsof -ti:5001 >/dev/null 2>&1; then
        warn "Port 5001 is in use, killing existing processes..."
        lsof -ti:5001 | xargs kill -9 2>/dev/null || true
        sleep 2
    fi
    
    # Iniciar Flask em background
    nohup python3 -c "
from app import app
print('🔥 Flask backend starting on http://localhost:5001')
app.run(debug=False, host='0.0.0.0', port=5001, threaded=True)
" > backend.log 2>&1 &
    
    BACKEND_PID=$!
    echo $BACKEND_PID > backend.pid
    
    cd ..
    
    # Aguardar backend inicializar
    info "Waiting for backend to start..."
    sleep 3
    
    # Verificar se backend está respondendo
    if curl -s http://localhost:5001/ >/dev/null 2>&1; then
        info "✅ Backend is running on http://localhost:5001"
    else
        warn "Backend may not be responding yet, check backend.log for details"
    fi
}

# Iniciar frontend
start_frontend() {
    log "Starting React frontend..."
    
    cd frontend/home-server-admin-frontend
    
    # Matar processos na porta 5173
    if lsof -ti:5173 >/dev/null 2>&1; then
        warn "Port 5173 is in use, killing existing processes..."
        lsof -ti:5173 | xargs kill -9 2>/dev/null || true
        sleep 2
    fi
    
    # Iniciar React em background
    nohup pnpm run dev --host > frontend.log 2>&1 &
    
    FRONTEND_PID=$!
    echo $FRONTEND_PID > frontend.pid
    
    cd ../..
    
    # Aguardar frontend inicializar
    info "Waiting for frontend to start..."
    sleep 5
    
    # Verificar se frontend está respondendo
    if curl -s http://localhost:5173/ >/dev/null 2>&1; then
        info "✅ Frontend is running on http://localhost:5173"
    else
        warn "Frontend may not be responding yet, check frontend.log for details"
    fi
}

# Função para parar os serviços
stop_services() {
    log "Stopping services..."
    
    # Parar backend
    if [ -f "backend/backend.pid" ]; then
        BACKEND_PID=$(cat backend/backend.pid)
        if kill -0 $BACKEND_PID 2>/dev/null; then
            kill $BACKEND_PID
            info "Backend stopped"
        fi
        rm -f backend/backend.pid
    fi
    
    # Parar frontend
    if [ -f "frontend/home-server-admin-frontend/frontend.pid" ]; then
        FRONTEND_PID=$(cat frontend/home-server-admin-frontend/frontend.pid)
        if kill -0 $FRONTEND_PID 2>/dev/null; then
            kill $FRONTEND_PID
            info "Frontend stopped"
        fi
        rm -f frontend/home-server-admin-frontend/frontend.pid
    fi
    
    # Matar processos nas portas como backup
    lsof -ti:5001 | xargs kill -9 2>/dev/null || true
    lsof -ti:5173 | xargs kill -9 2>/dev/null || true
}

# Trap para parar serviços ao sair
trap stop_services EXIT

# Processar argumentos da linha de comando
case "${1:-start}" in
    "start")
        check_dependencies
        setup_backend
        setup_frontend
        start_backend
        start_frontend
        
        echo ""
        log "🎉 Home Server Admin is running!"
        echo "=================================="
        info "Frontend: http://localhost:5173"
        info "Backend:  http://localhost:5001"
        echo ""
        info "Press Ctrl+C to stop all services"
        echo ""
        
        # Aguardar indefinidamente
        while true; do
            sleep 1
        done
        ;;
    "stop")
        stop_services
        log "All services stopped"
        ;;
    "status")
        echo "Service Status:"
        echo "==============="
        
        # Verificar backend
        if curl -s http://localhost:5001/ >/dev/null 2>&1; then
            echo -e "Backend:  ${GREEN}✅ Running${NC} (http://localhost:5001)"
        else
            echo -e "Backend:  ${RED}❌ Not running${NC}"
        fi
        
        # Verificar frontend
        if curl -s http://localhost:5173/ >/dev/null 2>&1; then
            echo -e "Frontend: ${GREEN}✅ Running${NC} (http://localhost:5173)"
        else
            echo -e "Frontend: ${RED}❌ Not running${NC}"
        fi
        ;;
    "logs")
        echo "Recent logs:"
        echo "============"
        echo ""
        echo -e "${BLUE}Backend logs:${NC}"
        tail -20 backend/backend.log 2>/dev/null || echo "No backend logs found"
        echo ""
        echo -e "${BLUE}Frontend logs:${NC}"
        tail -20 frontend/home-server-admin-frontend/frontend.log 2>/dev/null || echo "No frontend logs found"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|logs}"
        echo ""
        echo "Commands:"
        echo "  start   - Start both backend and frontend services"
        echo "  stop    - Stop all running services"
        echo "  status  - Check if services are running"
        echo "  logs    - Show recent logs from both services"
        exit 1
        ;;
esac

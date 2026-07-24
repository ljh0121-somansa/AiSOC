#!/bin/bash

# ===============================================================================
# AiSOC 로컬 개발 및 서비스 관리용 헬퍼 스크립트 (manage.sh)
#
# 이 스크립트는 로컬 PC에서 도커 컴포즈 기반의 AiSOC 서비스를 손쉽게 시작, 중지, 
# 재시작하고 데모 데이터를 주입할 수 있도록 돕는 유틸리티입니다.
# ===============================================================================

# 도커 컴포즈 파일 경로 지정
# COMPOSE_PATH="infra/compose/docker-compose.dev.yml"
COMPOSE_PATH="docker-compose.yml"
CONTAINER_PREFIX="aisoc-dev1"

# TTY 지원 여부에 따라 Docker 실행 옵션 동적 선택 (스크립트 및 자동화 대응)
if [ -t 0 ]; then
    DOCKER_OPTS="-it"
else
    DOCKER_OPTS="-i"
fi

# 색상 정의
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

function show_usage() {
    echo -e "사용법: ${BLUE}./manage.sh [명령어]${NC}"
    echo ""
    echo "명령어 목록:"
    echo -e "  ${GREEN}start${NC}       - AiSOC 전체 컨테이너를 구동합니다 (백그라운드)"
    echo -e "  ${GREEN}stop${NC}        - 구동 중인 모든 컨테이너를 중지하고 정리합니다"
    echo -e "  ${GREEN}restart${NC}     - 컨테이너들을 정지한 후 완전히 새로 빌드 및 재부팅합니다 (클린 리스타트)"
    echo -e "  ${GREEN}status${NC}      - 현재 구동 중인 컨테이너들의 구동 상태(ps)를 조회합니다"
    echo -e "  ${GREEN}seed${NC}        - 데이터베이스에 기본적인 15개 가상 침해 사례를 적재합니다 (표준 시드)"
    echo -e "  ${GREEN}seed-live${NC}   - 기존 데이터를 밀고, AI 에이전트를 가동시켜 실시간 분석을 개시합니다 (라이브 시드)"
    echo -e "  ${GREEN}logs [앱명]${NC} - 특정 서비스의 로그를 실시간으로 확인합니다 (예: ./manage.sh logs agents)"
    echo ""
    echo "예시:"
    echo "  ./manage.sh start"
    echo "  ./manage.sh seed-live"
    echo "  ./manage.sh logs agents"
}

# 인자값이 없을 경우 사용법 안내
if [ -z "$1" ]; then
    show_usage
    exit 0
fi

case "$1" in
    start)
        echo -e "${BLUE}[+] AiSOC 서비스를 시작합니다...${NC}"
        docker compose -f "$COMPOSE_PATH" up -d
        echo -e "${GREEN}[✔] 구동 명령이 전송되었습니다. './manage.sh status'로 상태를 확인하세요.${NC}"
        ;;
        
    stop)
        echo -e "${YELLOW}[-] AiSOC 서비스를 중지합니다...${NC}"
        docker compose -f "$COMPOSE_PATH" down
        echo -e "${GREEN}[✔] 모든 서비스가 안전하게 중지 및 정리되었습니다.${NC}"
        ;;
        
    restart)
        echo -e "${YELLOW}[*] 서비스를 클린 재시작합니다...${NC}"
        echo -e "${BLUE}[1/3] 기존 컨테이너를 중지하는 중...${NC}"
        docker compose -f "$COMPOSE_PATH" down
        echo -e "${BLUE}[2/3] ZooKeeper 동기화 불일치를 방지하기 위해 Kafka 데이터 볼륨을 초기화합니다...${NC}"
        docker volume rm ${CONTAINER_PREFIX}_kafka_data compose_kafka_data 2>/dev/null || true
        docker compose -f "$COMPOSE_PATH" build
        echo -e "${BLUE}[3/3] 컨테이너를 재생성하여 시작하는 중...${NC}"
        docker compose -f "$COMPOSE_PATH" up -d
        echo -e "${GREEN}[✔] 클린 재시작이 완료되었습니다!${NC}"
        ;;
        
    status)
        echo -e "${BLUE}[+] 컨테이너들의 현재 상태를 확인합니다:${NC}"
        docker compose -f "$COMPOSE_PATH" ps
        ;;
        
    seed)
        echo -e "${BLUE}[+] 표준 데모 데이터(15개 인시던트)를 적재하는 중...${NC}"
        if ! docker ps | grep -q "${CONTAINER_PREFIX}-api"; then
            echo -e "${RED}[ERROR] ${CONTAINER_PREFIX}-api 컨테이너가 켜져 있지 않습니다. 먼저 './manage.sh start'를 실행하세요.${NC}"
            exit 1
        fi
        docker exec $DOCKER_OPTS ${CONTAINER_PREFIX}-api python -m app.scripts.seed_demo
        echo -e "${GREEN}[✔] 표준 데모 데이터 적재가 완료되었습니다!${NC}"
        ;;
        
    seed-live)
        echo -e "${BLUE}[+] 기존 데이터를 리셋하고 AI 에이전트 분석을 강제 개시합니다 (라이브 시드)...${NC}"
        if ! docker ps | grep -q "${CONTAINER_PREFIX}-api"; then
            echo -e "${RED}[ERROR] ${CONTAINER_PREFIX}-api 컨테이너가 켜져 있지 않습니다. 먼저 './manage.sh start'를 실행하세요.${NC}"
            exit 1
        fi
        docker exec -e AGENTS_API_URL=http://agents:8084 $DOCKER_OPTS ${CONTAINER_PREFIX}-api python app/scripts/demo_seed.py --reset --kickoff-investigation
        echo -e "${GREEN}[✔] 에이전트 분석 시드가 성공적으로 구동되었습니다!${NC}"
        ;;
        
    logs)
        SERVICE_NAME="$2"
        if [ -z "$SERVICE_NAME" ]; then
            echo -e "${YELLOW}[!] 특정 서비스명을 지정하지 않았습니다. 전체 로그를 스트리밍합니다...${NC}"
            docker compose -f "$COMPOSE_PATH" logs -f --tail=100
        else
            echo -e "${BLUE}[+] 서비스 [$SERVICE_NAME]의 실시간 로그를 스트리밍합니다 (Ctrl+C로 종료):${NC}"
            docker compose -f "$COMPOSE_PATH" logs -f --tail=100 "$SERVICE_NAME"
        fi
        ;;
        
    *)
        echo -e "${RED}[ERROR] 알 수 없는 명령어입니다: $1${NC}"
        echo ""
        show_usage
        exit 1
        ;;
esac

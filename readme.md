# 스마트네트워크서비스 AD 과제

## 배경준	20213004	
## 하승준	20233114	
## 김도경	20203034

## 실행 방법
# 모든 설명은 Window 환경을 기준으로 한다. 우분투 환경 실행은 하단에
```bash
# (권장) 가상환경
# LTS 20.04 버전 권장,  LTS 22.04 호환, LTS 24.04 호환 x 
# Ryu SFC 를 위한 우분투 가상 환경
# Ubuntu를 활용 Ubuntu shell 창에 code . 으로 vsc 진입

sudo apt update
sudo apt install -y git python3.8 python3.8-venv python3.8-dev build-essential autoconf automake libtool libpcap-dev pkg-config curl

python3.8 -m venv .venv   # 반드시 3.8 이하 버전 사용 권장 
source .venv/bin/activate

pip install --upgrade pip
pip install wheel eventlet==0.30.2
pip install ryu==4.34

pip install requests

git clone https://github.com/mininet/mininet
cd mininet
sudo util/install.sh -a

sudo mkdir -p /var/run/openvswitch
sudo mkdir -p /etc/openvswitch

sudo ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
sudo ovsdb-server --remote=punix:/var/run/openvswitch/db.sock --remote=db:Open_vSwitch,Open_vSwitch,manager_options --pidfile --detach

sudo ovs-vswitchd --pidfile --detach
sudo ovs-vsctl show # 잘됬나 확인용

------

다른 터미널 열고 가상 환경 진입
source .venv/bin/activate
python3.8 -m ryu.cmd.manager --ofp-tcp-listen-port 6633 --wsapi-port 9090 ryu.app.simple_switch_13 ryu.app.ofctl_rest
----

또 다른 터미널 열고 가상환경 진입
source .venv/bin/activate
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo single,4 --switch ovsk,protocols=OpenFlow13

후에 윈도우에서 smartns.py 실행 Ryu SFC 제외 우분투 환경 없이도 정상 동작 

README에 16개 요구사항을 위 매핑처럼 체크리스트 표로 정리

스크린샷(각 탭) + 실행 방법(OS별) + 테스트 절차(포트 검사, 전송 모드 비교)

#----------------------------------------------------------------
## 우분투 환경 실행

sudo apt update
pip3 install ryu

git clone https://github.com/mininet/mininet
cd mininet
sudo util/install.sh -a

python3.8 -m ryu.cmd.manager --ofp-tcp-listen-port 6633 --wsapi-port 9090 ryu.app.simple_switch_13
# 다른 터미널 
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo single,3 --switch ovsk

#체크리스트
| 번호 | 요구사항 | GUI에서 입증하는 방법 |
|------|-----------|---------------------------|
| **1. IP 구성 확인** | ipconfig / ifconfig | **네트워크 진단 탭 → “IP 구성 확인” 버튼 클릭** → 자신의 IP 정보 출력 |
| **2. 바이트 정렬 함수** | hton/ntoh, inet_pton | 동일 탭에서 “hton/ntoh”, “inet_pton/ntop” 버튼 누르고 결과 값이 변환되어 출력되는지 확인 |
| **3. IP 주소 변환** | inet_pton/ntop | IPv4/IPv6 입력 → “변환” 버튼 → 바이너리/문자열 변환 결과 표시 |
| **4. DNS → IP** | gethostbyname | DNS 조회 입력 → “DNS 조회” 버튼 → IP 목록 출력되면 OK |
| **5. 서버 상태 확인** | 포트 오픈 검사 | “포트 오픈 검사”에 IP, Port 입력 → OPEN/CLOSED 결과 출력으로 입증 |
| **6. netstat 필터링** | LISTEN 포트 검색(9000 등) | “netstat 필터”에 포트 입력 → LISTEN 기록 출력되면 필터링 성공 |
| **7. TCP 서버 기능** | 서버 시작/정지 | “TCP 서버” 탭 → 서버 시작 → 로그창에 “서버 시작” 및 클라이언트 접속 로그 확인 |
| **8. TCP 클라이언트 기능** | 접속/전송/해제 | “TCP 클라이언트” 탭에서 접속 → 메시지 전송 → 서버 로그에서 수신 메시지 확인 |
| **9. 버퍼 조회** | SNDBUF, RCVBUF | “버퍼/소켓 탭”에서 조회 버튼 클릭 → 소켓 버퍼 사이즈 출력되면 OK |
| **10. 네트워크 그림판** | 드래그 선 그리기 + 브로드캐스트 | 그림판 탭에서 드래그 → 같은 서버에 접속 중인 **다른 클라이언트 화면에도 동일하게 선이 나타나면 브로드캐스트 기능 입증** |
| **11. FIXED(고정 길이) 전송** | 32바이트 고정 전송 | 클라에서 **FIXED 모드 선택 → 전송** → 서버 로그에서 정확히 32B 수신되는지 확인 |
| **12. VAR(가변 길이) 전송** | length + payload | VAR 모드 → 메시지 전송 → 서버 로그에서 “len = X, payload = …” 형태로 길이+데이터 구분되어 표시 |
| **13. MIX(고정+가변) 전송** | 4B 길이 + payload | MIX 모드 → 전송 → 서버 로그에서 **길이(4B) + 데이터(payload)**가 정상적으로 파싱됨 |
| **14. 전송 후 종료** | send 후 소켓 close | “전송 후 종료” 체크 → 전송 → 서버 로그에서 **recv 후 즉시 close()** 로그 확인 |
| **15. 멀티 스레드 동작** | 스레드 1개/클라이언트 | 두 클라이언트가 **동시에 전송** → 서버 로그에 “counter=1,2,3…” 순서대로 증가 → Lock으로 보호된 상태 입증 |
| **16. 임계영역 / Event 종료** | Lock() + Event 종료 | 서버 종료 버튼 클릭 → **각 스레드가 정리되고 모두 종료 로그 출력** → Event 기반 안전 종료 기능 입증 |



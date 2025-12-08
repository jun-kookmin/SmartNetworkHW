# 스마트네트워크서비스 AD 과제

## 배경준	20213004	
## 하승준	20233114	
## 김도경	20203034

## 실행 방법
```bash
# (권장) 가상환경
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install requests

python smart_net_suite.py

README에 16개 요구사항을 위 매핑처럼 체크리스트 표로 정리

스크린샷(각 탭) + 실행 방법(OS별) + 테스트 절차(포트 검사, 전송 모드 비교)

## 모든 터미널은 가상환경에 들어간 상태여야함
sudo apt update
sudo apt install python3 python3-venv python3-pip -y
pip install --upgrade pip

cd ~/바탕화면/smart  # 프로젝트 디렉토리
python3 -m venv ryu-env

source ryu-env/bin/activate

sudo apt install mininet -y

python3 -m ryu.cmd.manager ryu.app.ofctl_rest ryu.app.simple_switch_13

sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo=linear,4

curl http://127.0.0.1:8080/stats/flow/1 // 된건지 확인용 


# 스마트네트워크서비스 AD 과제

## 배경준	20213004	
## 하승준	20233114	
## 김도경	20203034

## 실행 방법
```
## bash
# (권장) 가상환경
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install requests

python smart_net_suite.py


## smartns.py 요구사항 매핑 체크리스트
| # | 요구 기능 | UI/버튼/탭 매핑 (smartns.py) | 상태 |
|---|---|---|---|
|1|IP 구성 확인 (ipconfig/ifconfig 자동)|네트워크 진단 탭 `IP 구성 확인` 버튼 → `do_ipconfig` (OS별 분기)|V|
|2|바이트 정렬 함수 (host↔network 16/32/64비트)|네트워크 진단 탭 `hton/ntoh 데모` → `do_hton`|V|
|3|IP 주소 변환 함수 (inet_pton/ntop)|네트워크 진단 탭 `IPv4 변환`/`IPv6 변환` → `do_inet4`, `do_inet6`|V|
|4|DNS/역방향 이름 변환|네트워크 진단 탭 `DNS 조회`, `역방향 조회` → `do_dns`, `do_reverse`|V|
|5|Server 상태 확인 (포트 오픈 검사)|네트워크 진단 탭 `포트 검사` → `do_check_port`|V|
|6|netstat -a -n -p tcp | findstr/grep 필터|네트워크 진단 탭 `netstat 필터` → `do_netstat` (Windows findstr, Unix grep)|V|
|7|GUI TCP 서버 상태 표시|TCP 서버 탭: 시작/정지 버튼, 접속 수/카운터 라벨, 로그 창, 이벤트/스레드(`server_stop_event`, `server_lock`) 기반|V|
|8|TCP 클라이언트 상태 표시|TCP 클라이언트 탭: 접속/해제, 전송모드 선택, 로그 (`cli_connect`, `cli_close`, `_cli_recv_loop`)|V|
|9|소켓 버퍼 상태 표시|버퍼/소켓 탭 `클라 소켓 버퍼 조회`, `임시 소켓 버퍼 조회` → `buf_client`, `buf_temp` (SO_SNDBUF/SO_RCVBUF)|V|
|10|네트워크 그림판 (드래그 & 서버 브로드캐스트)|네트워크 그림판 탭: 드래그 이벤트 → `_draw_move`, 서버 브로드캐스트 `_server_draw_broadcast_loop`|V|
|11|고정길이 전송 (FIXED)|클라이언트 전송모드 `FIXED(32B)` → `cli_send` + `pad_fixed`/서버 `_server_client_loop` `F`|V|
|12|가변길이 전송 (VAR, \\n 구분)|전송모드 `VAR(\\n)` → `cli_send` `V` + 서버 `_server_client_loop` `VAR` 처리|V|
|13|고정+가변 전송 (MIX, 4B length prefix)|전송모드 `MIX` → `cli_send` `M` + 서버 `_server_client_loop` `M` 처리|V|
|14|데이터 전송 후 종료|TCP 클라이언트 탭 `전송 후 종료` 체크 → `cli_send` 내부 `var_after_close`|V|
|15|멀티 스레드 동작|서버: accept 루프+클라이언트별 스레드 (`_server_accept_loop`, `_server_client_loop`), 공유 카운터 보호|V|
|16|임계영역/이벤트 연습|`threading.Lock`(`server_lock`)으로 공유카운터/리스트 보호, `threading.Event`(`server_stop_event`, `client_stop_event`)로 안전 종료|V|

## 추가 가이드
- 스크린샷(각 탭), 실행 방법(OS별), 테스트 절차(포트 검사·전송 모드 비교)를 README에 이어서 작성/업데이트 예정.
- 모든 터미널은 가상환경에 들어간 상태에서 실행하는 것을 권장합니다.

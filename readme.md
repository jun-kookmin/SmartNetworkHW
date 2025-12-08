# 스마트네트워크서비스 AD 과제

## 배경준	20213004	
## 하승준	20233114	
## 김도경	20203034

## 실행 방법
### 1 Windows(WSL)의 vscode를 기준, 상대 경로는 작성자의 폴더를 기준으로 함

```bash
# 기본 패키지 설치
Ubuntu에서 code . 으로 vscode 진입.

sudo apt update
sudo apt install -y python3 python3-venv python3-pip mininet curl

# 2. 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 3. 파이썬 패키지 설치
pip install --upgrade pip
pip install ryu requests eventlet

git clone https://github.com/mininet/mininet.git
cd mininet
sudo ./util/install.sh -a

# 4. Ryu 컨트롤러 실행 / 가상환경 권장 
python3 -m ryu.cmd.manager ryu.app.ofctl_rest ryu.app.simple_switch_13

# 5. Mininet 스위치 실행 / 별도 터미널, 같은 venv 상태에서 동작 권장
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo=linear,4
```

## smartns.py 요구사항 매핑 체크리스트
| # | 요구 기능 | UI/버튼/탭 매핑 (smartns.py) | 상태 |
|---|-----|-----|---|
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

### 1. IP 구성 확인
<img width="2309" height="1607" alt="image" src="https://github.com/user-attachments/assets/a1dbfacb-c5fc-424d-891e-9db97903cf9e" />

### 2. 바이트 정렬 함수
<img width="2339" height="1523" alt="image" src="https://github.com/user-attachments/assets/d10a8ac4-7ca7-40a9-96ed-4f0b2edc8d0d" />

### 3. IP 주소 변환 함수
<img width="2351" height="1582" alt="image" src="https://github.com/user-attachments/assets/138de91c-398a-467d-bff8-388281cf7b4c" />

### 4. DNS와 이름 변환
<img width="2340" height="1605" alt="image" src="https://github.com/user-attachments/assets/4213e663-03fd-4b04-93d8-8a6316271944" />

### 5. Server 상태 확인
<img width="2338" height="1609" alt="image" src="https://github.com/user-attachments/assets/f22b69f1-6a5e-4698-8cb1-586017d074e8" />

### 6. netstat -a -n -p tcp | findstr 9000
<img width="2336" height="1529" alt="image" src="https://github.com/user-attachments/assets/735b8197-b131-44b7-b725-71a2a0e759e8" />

### 7. GUI TCP 서버 함수 상태 표시
<img width="2342" height="1526" alt="image" src="https://github.com/user-attachments/assets/dabd4e20-8acd-4bcd-9324-ea2e372b7095" />

### 8. TCP 클라이언트 함수 상태 표시
<img width="1470" height="528" alt="image" src="https://github.com/user-attachments/assets/5cecedd3-b31e-485e-990e-0b6eb15025d7" />


### 9. 소켓 데이터 구조체(버퍼) 상태 표시
<img width="2325" height="1594" alt="image" src="https://github.com/user-attachments/assets/501a5a2d-d4f6-4a77-b5b4-409b91a4cc61" />
<img width="2338" height="1598" alt="image" src="https://github.com/user-attachments/assets/f60948f0-ca45-40c1-97c8-8860aa382631" />
<img width="2338" height="1601" alt="image" src="https://github.com/user-attachments/assets/c837cb6c-c7d1-4510-a657-b14ed5c98371" />

### 10. 네트워크 그림판
<img width="2879" height="1702" alt="image" src="https://github.com/user-attachments/assets/146c0388-763f-4db2-a008-56db5acaac0a" />
<img width="2352" height="1610" alt="image" src="https://github.com/user-attachments/assets/64208e19-94c8-4f40-bdbc-e9e614a53161" />

### 11. 고정길이 전송
<img width="2356" height="1526" alt="image" src="https://github.com/user-attachments/assets/5fe59ab5-50dc-4763-b01e-86a45234b043" />

### 12. 가변길이 전송
<img width="2339" height="1605" alt="image" src="https://github.com/user-attachments/assets/c61cc480-86ba-43cd-9673-8aa5c7ed91ea" />

### 13. 고정+가변 전송
<img width="2344" height="1582" alt="image" src="https://github.com/user-attachments/assets/e4785cdb-e807-4e84-840b-474aaecde0db" />

### 14. 데이터 전송 후 종료
<img width="2330" height="1601" alt="image" src="https://github.com/user-attachments/assets/02de5471-40bb-45b3-b117-c76f521d4fea" />

### 15. 멀티 스레드 동작
<img width="2875" height="1697" alt="image" src="https://github.com/user-attachments/assets/72b4ff9c-6f1a-4a00-952f-4a974d490e94" />

### 16. 임계영역/이벤트 연습
<img width="1422" height="592" alt="image" src="https://github.com/user-attachments/assets/70c0d8d0-536d-4228-902a-5fdb16fa86b6" />

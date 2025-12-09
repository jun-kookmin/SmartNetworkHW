# 스마트네트워크서비스 AD 과제

## 배경준	20213004	
## 하승준	20233114	
## 김도경	20203034

## 실행 방법
### 1 Windows(WSL)의 vscode를 기준, 상대 경로는 작성자의 폴더를 기준으로 함
#### 22.04 LTS, 20.04 LTS, python 3.8 버전 사용 
```bash
Ubuntu에서 `code .` 으로 vscode 진입.

# 기본 패키지 설치
sudo apt update
sudo apt install -y python3 python3-venv python3-pip mininet curl

# 2. 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 3. 파이썬 패키지 설치
pip install --upgrade pip
pip install ryu requests eventlet

# mininet 설치 
git clone https://github.com/mininet/mininet.git
cd mininet
sudo ./util/install.sh -a

# 4. Ryu 컨트롤러 실행 / 가상환경 권장 
python3 -m ryu.cmd.manager ryu.app.ofctl_rest ryu.app.simple_switch_13

# 5. Mininet 스위치 실행 / 별도 터미널, 같은 venv 상태에서 동작 권장
sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo=linear,4
```

## smartns.py 매핑 체크리스트
| # | 요구 기능 | 동작 확인 | 동작 여부 |
|---|-----|-----|---|
|1|IP 구성 확인|네트워크 진단 탭 `IP 구성 확인` 버튼|V|
|2|바이트 정렬 함수|네트워크 진단 탭 `hton/ntoh`|V|
|3|IP 주소 변환 함수|네트워크 진단 탭 `inet_pton/ntop(IPv4)`/`inet_pton/ntop(IPv6)`|V|
|4|DNS/이름 변환|네트워크 진단 탭 `DNS 조회`, `역방향 조회`|V|
|5|Server 상태 확인|네트워크 진단 탭 `포트 검사`|V|
|6|netstat -a -n -p tcp findstr 9000|네트워크 진단 탭 `netstat 필터`|V|
|7|GUI TCP 서버 함수 상태 표시|TCP 서버 탭 `서버 시작`, `서버 종료`|V|
|8|TCP 클라이언트 함수 상태 표시|TCP 클라이언트 탭 `접속`, `해제`|V|
|9|소켓 버퍼 상태 표시|버퍼/소켓 탭 `클라 소켓 버퍼 조회`, `임시 소켓 버퍼 조회`|V|
|10|네트워크 그림판|네트워크 그림판 탭 드래그|V|
|11|고정길이 전송 (FIXED)|TCP 클라이언트 탭 `FIXED(32B)`, `전송`|V|
|12|가변길이 전송 (VAR)|TCP 클라이언트 탭 `VAR(\n)`, `전송`|V|
|13|고정+가변 전송 (MIX)|TCP 클라이언트 탭 `MIX`, `전송`|V|
|14|데이터 전송 후 종료|TCP 클라이언트 탭 `전송 후 종료` 체크|V|
|15|멀티 스레드 동작|클라이언트별 스레드 `th = threading.Thread(target=self._server_client_loop, args=(cli, addr), daemon=True)`|V|
|16|임계영역/이벤트|`threading.Lock`으로 공유카운터/리스트 보호, `threading.Event`로 안전 종료|V|

### 1. IP 구성 확인
<img width="2309" height="1607" alt="image" src="https://github.com/user-attachments/assets/a1dbfacb-c5fc-424d-891e-9db97903cf9e" />

### 2. 바이트 정렬 함수
<img width="2346" height="1601" alt="image" src="https://github.com/user-attachments/assets/6cd178f8-9286-4243-bf0a-ebdd072f6344" />

### 3. IP 주소 변환 함수
<img width="2339" height="1523" alt="image" src="https://github.com/user-attachments/assets/d10a8ac4-7ca7-40a9-96ed-4f0b2edc8d0d" />

### 4. DNS와 이름 변환
<img width="2342" height="1527" alt="image" src="https://github.com/user-attachments/assets/f71d0810-5c36-4d05-8050-b5cff8705ca7" />
<img width="2333" height="1526" alt="image" src="https://github.com/user-attachments/assets/ac315884-4ca5-4434-9837-5bc97b0fbe92" />


### 5. Server 상태 확인
<img width="2339" height="1598" alt="image" src="https://github.com/user-attachments/assets/48f25a71-ac03-4345-9037-fece4020486c" />


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
<img width="2354" height="1522" alt="image" src="https://github.com/user-attachments/assets/fe6f6469-3676-46d7-b7b7-14b3e085036c" />


### 12. 가변길이 전송
<img width="2353" height="1525" alt="image" src="https://github.com/user-attachments/assets/af43791b-1816-4ed9-8361-ad61ecef25e9" />


### 13. 고정+가변 전송
<img width="2340" height="1523" alt="image" src="https://github.com/user-attachments/assets/02d3f686-4e07-49ad-9588-99f94dcba05d" />


### 14. 데이터 전송 후 종료
<img width="2339" height="1527" alt="image" src="https://github.com/user-attachments/assets/eb89ec6f-ab5d-47d3-8c28-8613f7d63db9" />


### 15. 멀티 스레드 동작
<img width="1469" height="114" alt="image" src="https://github.com/user-attachments/assets/290b8260-d307-44f1-a68c-2a92c0928f65" />
<img width="2875" height="1697" alt="image" src="https://github.com/user-attachments/assets/72b4ff9c-6f1a-4a00-952f-4a974d490e94" />

### 16. 임계영역/이벤트 연습
<img width="3840" height="1960" alt="image" src="https://github.com/user-attachments/assets/65146749-0501-4195-898a-373c90450e7b" />
<img width="3840" height="1966" alt="image" src="https://github.com/user-attachments/assets/553d2447-5576-4f91-a7ff-200501093ab9" />
<img width="1328" height="777" alt="image" src="https://github.com/user-attachments/assets/e84606e8-6c05-496c-865d-6c5d455ef7af" />

### 17. Ryu SFC
<img width="2343" height="1599" alt="image" src="https://github.com/user-attachments/assets/934e4663-2b3e-4b34-b478-a2bb35af41f0" />
<img width="2345" height="1606" alt="image" src="https://github.com/user-attachments/assets/d0f20073-76b6-45b9-abcf-0fc450251143" />
<img width="2336" height="1603" alt="image" src="https://github.com/user-attachments/assets/04e47a1f-f307-483d-ab57-1dd59aa6683c" />
<img width="2337" height="1598" alt="image" src="https://github.com/user-attachments/assets/e6edafe3-b725-4734-b468-b3c9cf03738e" />
<img width="2341" height="1598" alt="image" src="https://github.com/user-attachments/assets/ecee8eb8-9c7a-4259-b5d0-f006ee769d42" />






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

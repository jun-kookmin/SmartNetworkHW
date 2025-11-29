# 스마트네트워크서비스 AD 과제

## 배경준	20213004	
## 하승준	20233114	
## 김도경	20203034

## 실행 방법
# 모든 설명은 Window 환경을 기준으로 한다.
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

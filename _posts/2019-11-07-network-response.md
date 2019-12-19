---
layout: post
title: '[방화벽] 네트워크 문제 추척하기'
subtitle: 'network, analysis, response'
categories: management
tags: firewall
comments: true
---

> 이 글은 방화벽 운영에 필요한 정보를 정리한 글입니다. 출처: http://vnthf.logdown.com/posts/2016/06/21/-5

# 네트워크 문제 추적하기

`간단하게 정리한 내용이 좋아서 그대로 가져온 글`

## 서버 A가 서버 B와 통신할 수 없는 경우 당연한

이야기지만 클라이언트 혹은 서버 문제이다.

### 연결되어 있는지

먼저 클라이언트에서 살펴본다. `ethtool`을 이용해 네트워크연결을 확인해 볼 수 있다.
  
```bash
$ sudo ethtool eth0
```  
  
마지막줄의 Link detected가 yes라면 물리적으로 연결

### 네트워크의 인터페이스가 살아있는지

호스트의 네트워크 인터페이스가 올바르게 설정되어있는지 확인. IP가 있고 동작하는지..
  
```bash
$ sudo ifconfig eth0
```
  
ip주소가 있고 subnetmask가 있다면 제대로 설정되어 있는것임

인터페이스가 설정되어있지 않다면 sudo ifup eth0을 실행.

활성화 되지 않는다면

데비안은 /etc/network/interfaces

레드햇은 /etc/sysconfig/network_scripts/ifcfg-를 확인

### 로컬 네트워크에 있는가

자신만의 IP를 가졌는데 왜 IP 주소를 받아오지 못하는지 확인해야함. 먼저 기본게이트웨이 설정을 확인
  
```bash
$ sudo route -n
```
  
default로 시작하는 부분에 게이트웨이를 가지고 있는지 확인할 수 있음

이 정보가 없고 도달하려는 정보가 다른 서브넷이면 게이트웨이를 재 설정

데비안은 /etc/network/interfaces

레드햇은 /etc/sysconfig/network_scripts/ifcfg-를 확인

<br>

IP를 가져오는것을 DHCP를 통해서 한다면 DHCP가 올바르게 설정되어있는지를 확인하고 재설정

데비안
 
```bash
$ sudo service networking restart
```
  
레드햇
  
```bash
$ sudo service network start
```
  
그 후 게이트웨이에 핑을 보내서 핑이 간다면 정상.
  
```bash
$ ping -c 6 10.1.1.1
```
  
### DNS가 동작중인가

게이트웨이와 통신이 가능하다면 DNS가 작동하는지 확인해야함.
  
```bash
$ nslookup web1
Server: 10.1.1.3
Address: 10.1.1.3#53
Name: web1.example.net
Address: 10.1.2.5
```
  
nslookup을 이용해서 web1을 IP주소로 변환시켜주는지 확인해야함. 위와 같이 나오면 정상.

#### 설정된 도메인서버가 없거나 접근할 수 없는 도메인 서버
  
```bash
$nslookup web1
;; connection timed out; no servers could be reached
```
  
/etc/resolve.conf를 검토해 어떤 도메인 서버가 설정돼어 있는지 확인하고 아무것도 없으면 도메인서버를 추가해야함.
  
```bash
searcj example.net
naeserver 10.1.1.3
```
  
네임서버에 ping을 보낼 수 없고 ip주소가 동일한 서브넷에 있으면 네임서버는 완전히 다운됐다고 할 수 있음

#### 누락된 검색 경로 또는 도메인서버 문제
  
```bash
$nslookup web1
Server: 10.1.1.3
Address: 10.1.1.3#53
** server can't find web1: NXDOMAIN
```
  
이럴 경우 두가지 경우.

1) web1의 도메인명이 DNS검색 경로에 설정되어 있지 않은 경우.

도메인까지 포함한 전체주소로 nslookup을 날려보고 검색경로에 추가한다.

2) 도메인 서버에 이상이 있을 경우.

### 원격 호스트로 찾아갈 수 있는가?

dns문제를 제외하고 web1이 10.1.2.5로 정상변환되는 것을 확인했다면 원격호스트로 라우팅되는지도 확인해봐야함.
  
```bash
$ traceroute 10.1.2.5
```
  
패킷이 dev1에서 게이트웨이로 가고 그다음에 어떻게 가는지등등을 모두 보여줌.

출력 결과에 `*`이 보인다면 문제가 게이트웨이에 있다는 것임. 타임아웃이 되거나 서버가 다운된것을 의심.

### 원격 포트가 열려 있는가?

장비에 라우팅이 되는데 80번포트에 접근할 수 없어서 장애가 날 수도 있음
  
```bash
$ telnet 10.1.2.5 80
Trying 10.1.2.5 ...
telnet: Unable to connect to remote host: Connection refused
```
  
위와 같이 나타나면 포트가 다운됬거나 방홤벽이 접근을 차단한거임. 일단 텔넷이 작동을 한다는 것은 네트워킹에는 전혀 문제가 없다는것

방화벽과 같은 포트 테스팅에는 nmap이 더 적당. 진짜로 차단된 포트와 방화벽에 의하여 차단된 포트의 차이를 알려줌
  
```bash
nmap -p 80 10.1.2.5
Starting Nmap 4.62 (http://nmap.org) at 2009-02-05 18:49 PST
Interesting Ports on web1 (10.1.2.5):
PORT STATE SERVICE
80/tcp filtered http
```
  
### 로컬에서 원격 호스트 테스트하기

문제가 호스트 자체라면 80번포트를 사용할 수 있는지 테스트해야함

#### 리스닝 포트 테스트하기

80 포트에서 뭔가 리스닝을 하고 있는지 봐야함
  
```bash
$ sudo netstat -lnp | grep :80
tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 919/apache
```
  
사용중인 프로토콜/ 수신큐/ 송신큐/ 모든 IP에 대해 80번포트 리스닝 / 포트를 연 프로세스

#### 방화벽 규칙

리스닝이 잘되고 있으면 방화벽을 의심해야함
  
```bash
$ sudo /sbin/iptables -L
Chain INPUT (policy ACCEPT)
target port opt source destination
```
  
기본설정은 ACCEPT, DROP은 모든 패킷 차단.
  
```bash
$ sudo /sbin/iptables -L
Chain INPUT (policy ACCEPT)
target port opt source destination
REJECT tcp -- 0.0.0.0/0 0.0.0.0/0   tcp dpt:80 reject-with
```
  
위와 같이 있다면 80번 포트의 방화벽을 차단한 경우

## 느린 네트워크 문제 해결하기

### DNS문제

dns는 기본적으로 30초를 기다린 후 다른 DNS서버로 이동 그러나 예상치 못한 네트워크 성능저하를 일으키기도 함

dig나 nslookup, ping, traceroute, route, netstat, iptables등을 통해서 DNS문제를 확인해야함.

-n옵션을 사용해서 DNS문제는 제외하고 살펴 볼 수 있음.

### traceroute로 네트워크 속도저하 찾아내기

traceroute는 데이터가 어디를 통해서 흘러가는지 보여줌. 그래서 병목구간을 찾아서 느린문제를 해결 할 수 있음

###iftop으로 네트워크 대역폭을 사용하고 있는 것 찾아내기

top같이 네트워크 서버와 원격 Ip사이에서 대역폭을 사용하고 있는 연결목록을 보여줌

도메인이 느릴 경우 iftop도 같이 느려질 수 있어서 -n옵션을 사용하도록 권장

P키를 이용해 각 통신에 사용된 포트를 볼 수 있음. 그래서 어떤 서비스인지 netstat -lng를 이용해 확인 할 수 있음

## 패킷 수집

저수준의 문제를 해결 할 때 써야함. 양쪽 모두에서 수집하는게 효율적

### tcpdump

항상 루트로 실행 종료시키기 전까지 덤프를 뜸.
  
```bash
$ sudo tcpdump -n
```
  
특정 호스트로 필터링
  
```bash
$ sudo tcpdump -n host web1
$ sudo tcpdump -n not host web1
```
  
특정 포트로 필터링
  
```bash
$ sudo tcpdump -n port 53
$ sudo tcpdump -n port 80 or port 443
```
  
파일 쓰기 & 써지면서 모니터링
  
```bash
$ sudo tcpdump -n host web1 > outputfile
$ sudo tcpdump -n -l host web1 | tee outputfile
```
  
원시패킷 덤프 저장
  
```bash
$ sudo tcpdump -w output.pcap
```
  
저장 파일 크기 관리 기본 메가

output.pcap.1 -> pcap.2 이런 식으로 저장
  
```bash
$ sudo tcpdump -C 10 -w output.pcap
```

저장 수를 5개로 제한
  
```bash
$ sudo tcpdump -C 10 -W 5 -w output.pcap
```
  
저장한 파일을 재생
  
```bash
$ sudo tcpdump -n -r output.pcap
```
  
### 와이어샤크

원시패킷을 해석하고자하는 수요가 있을 때

이 포스트는 데브옵스를 읽고 정리한 내용입니다.

http://www.yes24.com/24/goods/8860423?scode=032&OzSrank=1

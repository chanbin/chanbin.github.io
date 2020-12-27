---
layout: post
title: '[분석] Incident_Response(Linux)'
subtitle: 'management, Incident, Response, Linux'
categories: management
comments: true
---

> 이 글은 침해사고 발생 시 수집해야 할 명령어들을 정리한 글입니다.

# Incident_Response(Linux)

<br>

## Accounts

### 1. cat /etc/group : 계정별 그룹 목록

### 2. passwd : 계정 목록

### 3. shadow : 계정별 패스워드 사용목록

### 4. w : 현재 접속 계정 목록

### 5. history : 현재 계정의 명령어 사용 기록

### 6. last -R : 계정별 현재 접속기록(pts : 원격, tty : 시리얼 콘솔)

### 7. lastlog : 계정별 마지막 접속 기록

<br>

## File

### 1. fls -r -m (sleuthkit) : 파일 목록(삭제된 파일 포함)

### 2. mactime -b (sleuthkit): 파일 목록별 생성 시간

<br>

## Network

### 1. arp : arp table

### 2. lsof : 프로세스 별로 열려있는 파일 정보

### 3. netstat -an : 네트워크 연결 상태

<br>

## OSinfo

### 1. date : 현재 시스템 시간

### 2. df -k : 디스크 사용 용량

### 3. hostname : 시스템 이름 조회

### 4. ifconfig -a : 네트워크 인터페이스

### 5. uname -a : 운영체제 버젼 정보

<br>

## Process

### 1. crontab -l : 스케쥴러 정보

### 2. ipcs : 계정별 메모리 사용정보

### 3. lsmod : 현재 사용중인 커널 모듈 정보

### 4. ps -eaf : 계정별 프로세스 사용정보

### 5. pstree -a : 계층 구조로 프로세스 조회

<br>

## WebLog

### 1. sudo find /var/log -name "access.log" : 

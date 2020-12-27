---
layout: post
title: '[분석] Incident_Response(Linux)'
subtitle: 'threat, Incident, Response, Linux'
categories: threat
comments: true
---

> 이 글은 침해사고 발생 시 수집해야 할 명령어들을 정리한 글입니다.

# Incident_Response(Linux)

## Accounts

### 1. group : 

### 2. history : 

### 3. last -R : 

### 4. lastlog : 

### 5. passwd : 

### 6. shadow : 

### 7. w : 

###File

### 1. fls -r -m (sleuthkit) : 

### 2. mactime -b (sleuthkit): 

###Network

### 1. arp : 

### 2. lsof : 

### 3. netstat -an : 

###OSinfo

### 1. date : 

### 2. df -k : 

### 3. hostname : 

### 4. ifconfig -a : 

### 5. localtime : 

### 6. timezone : 

### 7. uname -a : 

###process

### 1. crontab -l : 

### 2. ipcs -u : 

### 3. lsmod : 

### 4. ps -eaf : 

### 5. pstree -a : 

###weblog

### 1. sudo find /var/log -name "access.log" : 

### 2. ipcs -u : 
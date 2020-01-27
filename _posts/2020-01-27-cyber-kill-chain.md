---
layout: post
title: '[위협] Cyber Kill Chain'
subtitle: 'threat, Cyber, Kill Chain, Cheet Sheet'
categories: threat 
comments: true
---

> 이 글은 사이버 공격 과정을 정리한 글입니다.
> 출처: https://www.varonis.com/blog/cyber-kill-chain/

# Cyber Kill Chain

![](https://chanbin.github.io/assets/img/kill-chain/kill-chain1.PNG)
> 출처: https://www.varonis.com/blog/cyber-kill-chain/

###내부 공격인지 외부 공격인지에 관계없이, 각 단계는 사이버 공격에서 다양한 유형의 활동과 관련이 있다.

## 1. Reconnaissance (정찰)<br>
정찰 단계: 공격자는 일반적으로 공격 대상 및 전략을 수립하기 위해, 외부에서 시스템의 환경을 점검한다.<br>
The observation stage: attackers typically assess the situation from the outside-in, in order to identify both targets and tactics for the attack.

## 2. Intrusion (침입)<br>
공격자들이 정찰 단계에서 발견한 것들을 기반으로 시스템에 침투한다. 종종 악성 프로그램이나 보안 취약점을 활용한다.<br>
Based on what the attackers discovered in the reconnaissance phase, they’re able to get into your systems: often leveraging malware or security vulnerabilities.

## 3. Exploitation (시스템 악용)<br>
더 나은 발판을 마련하기 위해 취약성(vulnerabilities)을 악용하고, 시스템에 악의적인 코드를 전송하는 단계이다.<br>
The act of exploiting vulnerabilities, and delivering malicious code onto the system, in order to get a better foothold.

## 4. Privilege Escalation (권한 상승)<br>
공격자는 종종 더 많은 데이터와 사용 권한에 접근하기 위해 시스템 상에서 더 많은 권한이 필요하다. 이를 위해 공격자들은 종종 관리자 권한으로 확대한다.<br>
Attackers often need more privileges on a system to get access to more data and permissions: for this, they need to escalate their privileges often to an Admin.

## 5. Lateral Movement (수평 이동, 다른 시스템 및 다른 계정으로 이동)<br>
공격자는 일단 시스템에 들어가면 다른 시스템과 계정으로 이동하여 더 높은 사용권한, 더 많은 데이터, 시스템에 대한 더 큰 액세스 권한(leverage,영향력)을 얻을 수 있다.<br>
Once they’re in the system, attackers can move laterally to other systems and accounts in order to gain more leverage: whether that’s higher permissions, more data, or greater access to systems.

## 6. Obfuscation / Anti-forensics (혼란스럽게 / 복구 하거나 찾기 힘들도록)<br>
사이버 공격을 성공적으로 수행하기 위해서, 공격자들은 본인들의 자취를 감출 필요가 있다. 이 단계에서 그들은 거짓 흔적을 남기거나, 데이터를 손상시키고 로그를 삭제하여 포렌식팀을 혼란스럽게 하거나 분석 속도를 늦춘다.<br>
In order to successfully pull off a cyberattack, attackers need to cover their tracks, and in this stage they often lay false trails, compromise data, and clear logs to confuse and/or slow down any forensics team.

## 7. Denial of Service (서비스 거부)<br>
공격을 감시, 추적 또는 차단하는 것을 막기 위해 사용자 및 시스템에 대한 정상적인 액세스를 중단시킨다.<br>
Disruption of normal access for users and systems, in order to stop the attack from being monitored, tracked, or blocked

## 8. Exfiltration (정보 반출)<br>
추출 단계: 손상된 시스템에서 데이터를 가져온다.<br>
The extraction stage: getting data out of the compromised system.

<br>
![](https://chanbin.github.io/assets/img/kill-chain/kill-chain2.PNG)
> 출처: https://www.varonis.com/blog/cyber-kill-chain/ 

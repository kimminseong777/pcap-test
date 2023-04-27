# report pcap test
---
## 과제
송수신되는 packet을 capture하여 중요 정보를 출력하는 C/C++ 기반 프로그램을 작성하라.

1. Ethernet Header의 src mac / dst mac
2. IP Header의 src ip / dst ip
3. TCP Header의 src port / dst port
4. Payload(Data)의 hexadecimal value(최대 10바이트까지만)

## 실행
    syntax: pcap-test <interface>
    sample: pcap-test wlan0

## 상세

TCP packet이 잡히는 경우 "ETH + IP + TCP + DATA" 로 구성이 된다. 이 경우(TCP packet이 잡혔다고 판단되는 경우만)에만 1~4의 정보를 출력하도록 한다(Data의 크기가 0여도 출력한다).

각각의 Header에 있는 특정 정보들(mac, ip, port)를 출력할 때, 노다가(packet의 시작위치로부터 일일이 바이트 세어 가며)로 출력해도 되는데 불편함.

이럴 때 각각의 Header 정보들이 structure로 잘 선언한 파일이 있으면 코드의 구성이 한결 간결해진다. 앞으로 가급적이면 네트워크 관련 코드를 작성할 할 때에는 libnet 혹은 자체적인 구조체를 선언하여 사용하도록 한다.

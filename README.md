# pyrodump

## How to use

1. pip install -r requirements.txt
2. sudo python3 pyrodump.py <interface>
  
### 목차

- [Airodump-ng Analysis](#Airodump-ng-Analysis)
  - [AP List](#AP-List)
  - [Station List](#Station-List)
- [Pyrodump Configuration](#Pyrodump-Configuration)
- [Frames Analysis](#Frames-Analysis)
- [Infomation](#Infomation)
  - [Whether to connect](#Whether-to-connect)
  - [Wheher to No data, QoS data](#Wheher-to-No-data-QoS-data)

## Airodump-ng Analysis

- ### AP List

- ### Station List

## Pyrodump Configuration

## Frames Analysis
Beacon, Probe Request, Probe Response, Data Frames 각 프레임을 airodump-ng로 보면 다음과 같이 나타난다.

- ### 1. Beacon
Wireshark에서 Beacon Frame에 대한 정보만을 얻기위해서는 Display filter에 **wlan.fc.type_subtype==8**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788669-00120b80-21c4-11e9-8a00-c764bf16ee0d.png" width=1000></p>
  
가상 무선 어댑터를 생성한 후 생성한 가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Beacon Frame을 보내면 다음과 같이 나타난다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51803144-dc6ac600-2294-11e9-920a-8a4f5714947b.png" width=500></p>

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51803147-ed1b3c00-2294-11e9-9d67-35232ee34c7e.png" width=500></p>

#Data, #/s를 제외하고 AP 리스트에 대한 부분들이 변경되는 것을 확인할 수 있다.(Station 목록에 생성된 부분은 Wireshark에서는 확인할 수 없었으며 가상 어댑터에서 airodump-ng를 실행하면 보인다.)

- ### 2. Probe Request
Wireshark에서 Probe Request Frame에 대한 정보만을 얻기위해서는 Display filter에 **wlan.fc.type_subtype==4**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788793-56337e80-21c5-11e9-9a8c-a38031130e77.png" width=1000></p>
  
가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Probe Request Frame을 보내면 다음과 같이 나타난다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51803082-21dac380-2294-11e9-849d-5e2eb241e6d3.png" width=500></p>

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51803079-0c659980-2294-11e9-99d9-40bba00fd75d.png" width=500></p>

BSSID를 제외하고 Station 리스트에 대한 부분들이 변경되는 것을 확인할 수 있다.

그리고 Station 목록의 Frames는 같은 출발지(Station)가 발견되면 카운트가 1씩 늘어나는 것을 확인하였다.

가끔씩 AP 리스트가 추가되는데 이 부분에 대해서는 파악하지 못했다.

- ### 3. Probe Response
Wireshark에서 Probe Response Frame에 대한 정보만을 얻기위해서는 Display filter에 **wlan.fc.type_subtype==5**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788817-bfb38d00-21c5-11e9-80c6-3e7037abe7af.png" width=1000></p>
  
가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Probe Response Frame을 보내면 다음과 같이 나타난다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51802966-ba704400-2292-11e9-82db-df8b69591d1c.png" width=500></p>
  
<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51802978-dbd13000-2292-11e9-9527-30de0dfa86f8.png" width=500></p>
  
Beacons, #Data, #/s, CH를 제외하고 AP 리스트에 대한 부분들이 변경되는 것을 확인할 수 있다.

- ### 4. Data Frames(To Ds == 1 and From Ds ==0)
Wireshark에서 Data Frames(To Ds == 1 and From Ds ==0)에 대한 정보만을 얻기 위해서는 Display filter에 **wlan.fc.type==2 and wlan.fc.tods==1 and wlan.fc.fromds==0**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788905-4bc5b480-21c6-11e9-9c6b-c4dfd3405ac3.png" width=1000></p>
  
가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Data Frame(To Ds == 1 and From Ds == 0)을 보내면 다음과 같이 나타난다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51802764-75e3a900-2290-11e9-8111-7ca19f5a8b26.png" width=500></p>

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51802752-4e8cdc00-2290-11e9-9c9f-294291455e7c.png" width=500></p>
  
AP 리스트에서는 BSSID, #Data, #/s, CH, ENC가 변경되는 것을 확인하였고

Station 리스트에서는 BSSID, STATION, PWR, Rate, Lost, Frames가 변경되는 것을 확인하였다.

그리고 Station 리스트의 Frames는 같은 출발지(Station)가 발견되면 카운트가 1씩 늘어나는 것을 확인하였고 Data Frame 중 no data일 경우에는 AP 목록의 #Data가 올라가지 않는 것을 확인하였다.
  
- ### 5. Data Frames(To Ds == 0 and From Ds == 1)
Wireshark에서 Data Frames(To Ds == 0 and From Ds == 1)에 대한 정보만을 얻기 위해서는 Display filter에 **wlan.fc.type==2 and wlan.fc.tods==0 and wlan.fc.fromds==1**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788925-aa8b2e00-21c6-11e9-989d-c053d3014fa4.png" width=1000></p>
  
가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Data Frame(To Ds == 0 and From Ds == 1)을 보내면 다음과 같이 나타난다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51802865-729ced00-2291-11e9-8279-f451c81866af.png" width=500></p>

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51802860-644ed100-2291-11e9-84b1-2628383013f1.png" width=500></p>

AP 리스트에서는 BSSID, PWR, #Data, #/s, ENC가 변경되는 것을 확인하였고

Station 리스트에서는 BSSID, STATION, Rate, Frames가 변경되는 것을 확인하였다.

가끔씩 Station 리스트가 추가되는데 이 부분에 대해서는 파악하지 못했다.

## Infomation

- ### Whether to connect

다음 [사이트](http://www.ktword.co.kr/abbr_view.php?nav=2&m_temp1=4899&id=913)를 참고하면 다음과 같이 To Ds bit가 1일 때 AP와 Station이 연결되었다는 것을 알 수 있다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51790026-55a1e480-21d3-11e9-8e29-cb7b4fcd95cc.png" width=500></p>
  
- ### Wheher to No data, QoS data

다음 [사이트](http://www.ktword.co.kr/abbr_view.php?nav=2&choice=map&id=761&m_temp1=1170)를 참고하면 다음과 같이 비트위치 b6 1일 경우 No Data, b7이 1일 경우 QoS Data인 것을 알 수 있다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51789993-dd3b2380-21d2-11e9-897b-24577c4673b8.png" width=500></p>

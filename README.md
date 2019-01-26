# pyrodump

## How to use

1. pip install -r requirements.txt
2. sudo python3 pyrodump.py <interface>

## Frames Analysis
Beacon, Probe Request, Probe Response, Data Frames 각 프레임을 airodump-ng로 보면 다음과 같이 나타난다.

### 1. Beacon
Wireshark에서 Beacon Frame에 대한 정보만을 얻기위해서는 Display filter에 **wlan.fc.type_subtype==8**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788669-00120b80-21c4-11e9-8a00-c764bf16ee0d.png" width=1000></p>
  
가상 무선 어댑터를 생성한 후 생성한 가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Beacon Frame을 보내면 다음과 같이 나타난다.

#Data, #/s를 제외하고 AP 목록에 대한 부분들이 변경되는 것을 확인할 수 있다.(Station 목록에 생성된 부분은 Wireshark에서는 확인할 수 없었으며 가상 어댑터에서 airodump-ng를 실행하면 보인다.)

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51789055-60a34780-21c8-11e9-8a15-e5a408da732d.png" width=500></p>

### 2. Probe Request
Wireshark에서 Probe Request Frame에 대한 정보만을 얻기위해서는 Display filter에 **wlan.fc.type_subtype==4**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788793-56337e80-21c5-11e9-9a8c-a38031130e77.png" width=1000></p>
  
가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Probe Request Frame을 보내면 다음과 같이 나타난다.

BSSID, Rate를 제외하고 Station 목록에 대한 부분들이 변경되는 것을 확인할 수 있다.

그리고 Station 목록의 Frames는 같은 출발지(S)가 발견되면 카운트가 1씩 늘어나는 것을 확인하였다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51789212-d65be300-21c9-11e9-82c4-9e04dad4a43b.png" width=500></p>

### 3. Probe Response
Wireshark에서 Probe Response Frame에 대한 정보만을 얻기위해서는 Display filter에 **wlan.fc.type_subtype==5**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788817-bfb38d00-21c5-11e9-80c6-3e7037abe7af.png" width=1000></p>
  
가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Probe Response Frame을 보내면 다음과 같이 나타난다.

Beacons, #Data, #/s를 제외하고 AP 목록에 대한 부분들이 변경되는 것을 확인할 수 있다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51789380-a3b2ea00-21cb-11e9-8208-773dd084bd57.png" width=500></p>

### 4. Data Frames(To Ds == 1 and From Ds ==0)
Wireshark에서 Data Frames(To Ds == 1 and From Ds ==0)에 대한 정보만을 얻기위해서는 Display filter에 **wlan.fc.type==2 and wlan.fc.tods==1 and wlan.fc.fromds==0**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788905-4bc5b480-21c6-11e9-9c6b-c4dfd3405ac3.png" width=1000></p>
  
가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Beacon Frame을 보내면 다음과 같이 #Data, #/s를 제외하고 AP 목록에 대한 부분들이 변경되는 것을 확인할 수 있다.(Station 목록에 생성된 부분은 Wireshark에서는 확인할 수 없었으며 가상 어댑터에서 airodump-ng를 실행하면 보인다.)

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51789055-60a34780-21c8-11e9-8a15-e5a408da732d.png" width=500></p>
  
### 5. Data Frames(To Ds == 0 and From Ds == 1)
Wireshark에서 Data Frames(To Ds == 0 and From Ds == 1)에 대한 정보만을 얻기위해서는 Display filter에 **wlan.fc.type==2 and wlan.fc.tods==0 and wlan.fc.fromds==1**를 입력한다.

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51788925-aa8b2e00-21c6-11e9-989d-c053d3014fa4.png" width=1000></p>
  
가상 무선 어댑터에 대해 airodump-ng를 실행하고 tcpreplay로 Beacon Frame을 보내면 다음과 같이 #Data, #/s를 제외하고 AP 목록에 대한 부분들이 변경되는 것을 확인할 수 있다.(Station 목록에 생성된 부분은 Wireshark에서는 확인할 수 없었으며 가상 어댑터에서 airodump-ng를 실행하면 보인다.)

<p align="center"><image src = "https://user-images.githubusercontent.com/39123255/51789055-60a34780-21c8-11e9-8a15-e5a408da732d.png" width=500></p>

# NetworkGuardian

<img src="https://github.com/ucstove/NetworkGuardian/blob/main/Logo%20w_o%20Background.png" alt="NetworkGuardian Logo" width="200">


## Problem Statement

With the growing IoT networks in homes and small businesses, weak spots in LANs have increased. Often, IoT devices are not equipped with strong industrial cybersecurity measures, leaving important home appliances open to risk [1]. Often, artificial intelligence enables cyberattacks that are occurring more frequently than before. The rapid increase of attacks and vulnerabilities have left the regular homeowner and small business owner in need of an accessible and reliable cybersecurity system for their networks. Cybersecurity systems on LANs are often overpriced for the service provided. The main alternative is to make your own system, which requires technical skills in the field and therefore, creates a barrier to entry in cybersecurity. This project is extremely relevant to the field of computer science and computer engineering due to the application of cybersecurity, machine learning, and embedded IoT MCUs.

## System Features
The system will include a machine learning model that will look at packets, traffic patterns, timing frequency, and behavior over time on the network. The models we are looking into are supervised multi-class models (Random Forest, XGBoost), one-class models (Isolation Forest, autoencoders), and semi-supervised models (Self-training, PU learning) . This machine learning model will be imported onto a Raspberry Pi to read and detect the packets as they are sent throughout the network. The Raspberry Pi will also act as a server to store the data in an SQL database, which will allow for easy storage of relevant malicious data and information. This allows for the system to be disconnected from the internet and work independently. Attached to the Raspberry Pi will be an ALFA wifi antenna to pick up the network traffic from all devices, so that all packets sent can be scanned and checked. ESP32 MCUs with wifi chips will be used to model the devices on the IoT LAN. The ESP32s will be able to communicate with each other and send packets just like a network would. A web user interface will be implemented into the system as well. This UI will display any malicious data and information the machine learning model detects for the user to be aware of what’s happening. It will also include the type of attack, timestamps, and any other important information needed to help resolve the issue.

## License

[MIT](https://choosealicense.com/licenses/mit/)

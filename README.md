# WakeOnLan
Simple WakeOnLan WebUI with Python+Flask


## Install
Root access is required.

```sh
cd /opt
git clone https://github.com/arnaudcoquelet/WakeOnLan.git
```


### Enable systemd 
Go to /opt/WakeOnLan/systemd and look at the README

```sh
cd /opt/WakeOnLan/systemd
cp wakeonlan /etc/systemd/system/.

systemctl enable wakeonlan.service
```

### Start with systemd
```sh
systemctl start wakeonlan
```


## FAQ

Install pip packages:
```sh
pip install -r requirements.txt
```


Install Blitzdb from github:
```sh
pip install https://github.com/adewes/blitzdb/zipball/master --upgrade
```

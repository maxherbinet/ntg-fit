# fit
firewall inspection tester

IP Reputation Testing - Zeus tracker  
AV Testing - VX Vault/Eicar  
WF blocking - Chrome Malicious Website list  
APP Ctrl - Application control triggers  
Good Web Traffic - Good web traffic   

# Installing

FIT runs under python3, the recommend installation menthod is to use pyvenv. 

```
pyvenv env
source env/bin/activate
pip install -r requirements.txt
```

FIT also requires that you have PhantomJS installed. Please use your platform appropriate method to install PhantomJS

# Screenshot

![screenshot](https://github.com/infamy/fit/raw/master/screenshot.png)

# Using FIT

--srcip {ip} / -s {ip}  
Let's you set the source IP used by fit. You can use multiple -s/--srcip to set multiple source IPs. This increases the number of clients seen. You will need to setup your network card to use a unique MAC per IP, or the reported results will not be as desiered.

--loop  
Option on the ```all``` command. Will run the traffic in a loop, useful in a lab style enviroment. 

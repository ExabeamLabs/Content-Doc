#### Parser Content
```Java
{
Name = asa-aaa-vpn-stop
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = Splunk
    # AAA log messages start with 109
    #"Dec 12 01:29:48 asaserver.mgm.se.om Dec 12 2014 01:29:48 asaserver : %ASA-5-109012: Authen Session End: user 'joe', sid 128500, elapsed 36001 seconds"
    DataType = "vpn-end"
    TimeFormat = "MMM dd yyyy HH:mm:ss"
    Conditions = [ "Authen Session End:" ]
    Fields = [ """\s({host}[^\s]{1,2000})\s({time}[a-zA-Z]{3} \d\d \d\d\d\d \d\d:\d\d:\d\d).+Authen Session End: user '({user}[^']{1,2000})'""" ]
  }
```
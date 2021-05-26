#### Parser Content
```Java
{
Name = aruba-controller-failed-nac-logon
  Vendor = HP
  Product = Aruba Wireless controller
  Lms = Splunk
  DataType = "nac-failed-logon"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """authmethod=""", """servername=""", """apname=""", """bssid=""", """Authentication failed""" ]
  Fields = [
   """({time}\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
   """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\+""",
   """\d\d\d\d\s{1,100}({host}[^\s]{1,2000})\s(authmgr|stm)\[({event_code}\d{1,100})\]""",
   """username=(({domain}[^\\\s]{1,2000})\\)?({user}[^\s]{1,2000})"""   
   """userip=(0.0.0.0|({src_ip}[a-f0-9.]{1,2000}))""",
   """usermac=({src_mac}[a-f0-9:]{1,2000})""",
   """bssid=({dest_host}[a-f0-9:]{1,2000})""",
   """serverip=({auth_server}[a-f0-9.]{1,2000})""",
   """authmethod=({auth_method}[^\s]{1,2000})""",
   """User\sAuthentication\s({outcome}[\w]{1,2000})"""
  ]
}
```
#### Parser Content
```Java
{
Name = aruba-controller-failed-nac-logon
  Vendor = HP Aruba
  Product = Aruba Wireless controller
  Lms = Splunk
  DataType = "nac-failed-logon"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """authmethod=""", """servername=""", """apname=""", """bssid=""", """Authentication failed""" ]
  Fields = [
   """({time}\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
   """\d\d\d\d\s+({host}[^\s]+)\s(authmgr|stm)\[({event_code}\d+)\]""",
   """username=({user}[^\s]+)""",
   """userip=({src_ip}[a-f0-9.]+)""",
   """usermac=({src_mac}[a-f0-9:]+)""",
   """bssid=({ssid}[a-f0-9:]+)""",
   """serverip=({auth_server}[a-f0-9.]+)""",
   """authmethod=({auth_method}[^\s]+)""",
   """User\sAuthentication\s({outcome}[\w]+)"""
  ]
}
```
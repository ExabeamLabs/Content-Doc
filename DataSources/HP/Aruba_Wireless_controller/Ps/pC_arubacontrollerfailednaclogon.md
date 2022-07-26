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
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """({time}\w{3}\s\d\d\s\d\d:\d\d:\d\d\s\d\d\d\d)""",
   """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\+""",
   """\d\d:\d\d:\d\d\s{1,100}(\d\d\d\d\s{1,100})?({host}[^\s]{1,2000})\s(authmgr|stm|dot1x-proc:\d{1,100})\[({event_code}\d{1,100})\]""",
   """username=(host\/({src_host}[\w\-.]{1,2000})|({user_email}[^@=]{1,2000}@[^\.]{1,2000}\.[^=]{1,2000})|(({domain}[^\\\s]{1,2000})\\)?({user}[^\s]{1,2000}))\s{1,2000}\w{1,2000}="""   
   """userip=(0.0.0.0|({src_ip}[a-f0-9.]{1,2000}))""",
   """usermac=({src_mac}[a-f0-9:]{1,2000})""",
   """bssid=({dest_host}[a-f0-9:]{1,2000})""",
   """servername=(Internal|({dest_host}[\w\-.]{1,2000}))\s""",
   """serverip=({auth_server}[a-f0-9.]{1,2000})""",
   """authmethod=({auth_method}[^\s]{1,2000})""",
   """User\sAuthentication\s({outcome}[\w]{1,2000})"""
  ]


}
```
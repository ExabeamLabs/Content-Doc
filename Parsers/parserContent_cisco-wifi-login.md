#### Parser Content
```Java
{
Name = cisco-wifi-login
  Vendor = Cisco
  Product = Cisco WiFi
  Lms = Direct
  DataType = "logon"
  TimeFormat = "yyyy年  MM月 dd日 金曜日 HH:mm:ss"
  Conditions = [ """ ccx-client """ , """EAP-Assoc""", """日 金曜日 """ ]
  Fields = [
    """\[({time}\d{4}年  \d+月 \d+日 金曜日 \d\d:\d\d:\d\d)""",
    """\[({dest_ip}[a-fA-F\d\.:]+)\]\s({dest_mac}[a-fA-F\d\.:]+)\s\S+\s+::\s+ccx-client\s+({host}\S+)""",
  ]
  DupFields = [ "host->auth_server" ]
}
```
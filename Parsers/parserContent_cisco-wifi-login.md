#### Parser Content
```Java
{
Name = cisco-wifi-login
  Vendor = Cisco
  Product = Cisco WiFi
  Lms = Direct
  DataType = "logon"
  TimeFormat = "yyyy???  MM??? dd??? ????????? HH:mm:ss"
  Conditions = [ """ ccx-client """ , """EAP-Assoc""", """??? ????????? """ ]
  Fields = [
    """\[({time}\d{4}???  \d+??? \d+??? ????????? \d\d:\d\d:\d\d)""",
    """\[({dest_ip}[a-fA-F\d\.:]+)\]\s({dest_mac}[a-fA-F\d\.:]+)\s\S+\s+::\s+ccx-client\s+({host}\S+)""",
  ]
  DupFields = [ "host->auth_server" ]
}
```
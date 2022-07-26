#### Parser Content
```Java
{
Name = citrix-device-aaa-auth-failed
  Vendor = Citrix
  Product = Citrix Netscaler VPN
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ AAA Message """, """Authentication failed""" ]
  Fields = [
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100})\s{0,100}GMT""",
    """GMT\s{0,100}({host}[\w\.\-]{1,2000})([^:]{0,2000})?\s:\s{0,100}({event_code}[^:]{1,2000}?)\s{0,100}[\d\s]{1,2000}:\s{0,100}"{1,20}({failure_reason}.+?)\s{0,100}for user\s{0,100}(({user_email}[^@\s"]{1,2000}@[^"\s]{1,2000})|(({domain}[^\s\\\/"]{1,2000})[\\\/]{1,20})?(\*|({user}[^\s"]{1,2000})))"""
  ]


}
```
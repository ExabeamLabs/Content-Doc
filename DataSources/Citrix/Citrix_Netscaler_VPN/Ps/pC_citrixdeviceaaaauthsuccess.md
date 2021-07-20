#### Parser Content
```Java
{
Name = citrix-device-aaa-auth-success
  Vendor = Citrix
  Product = Citrix Netscaler VPN
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "MM/dd/yyyy:HH:mm:ss"
  Conditions = [ """ AAA Message """, """Succeeded policy for user""" ]
  Fields = [
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100})\s{0,100}GMT""",
    """GMT\s{0,100}({host}[^:\s]{1,2000})(\s\S+)?\s:\s{0,100}({event_code}(\w+\s{1,100}){3})[^:]{1,2000}:\s{0,100}"{1,20}({event_name}.+)\s{0,100}for user\s{0,100}({user}[^\s]{1,2000})\s{0,100}=\s{0,100}({auth_method}[^"]{1,2000})"{1,20}""",
    """GMT\s{0,100}({host}[^:\s]{1,2000})(\s\S+)?\s:\s{0,100}({event_code}(\w+\s{1,100}){2}\w+)\s{1,100}[^:]{1,2000}:\s{0,100}"{1,20}({event_name}.+)\s{1,100}for user\s{0,100}({user}[^\s]{1,2000})\s{0,100}=\s{0,100}({auth_method}[^"]{1,2000})"{1,20}"""
  ]
  DupFields = ["host->src_host"]
}
```
#### Parser Content
```Java
{
Name = raw-asa-113005-1
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ "-113005:", "AAA user authentication Rejected :", ": user =", ": reason =" ]
  Fields = [
    """({time}\d{1,100}\s{1,100}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100})\s{1,100}UTC\s{1,100}({host}[^\s]{1,2000})\s{1,100}:\s{1,100}({event_code}[^\s]{1,2000}):\s{1,100}({event_name}.+?)\s{1,100}:""",
    """reason\s{1,100}=\s{1,100}({failure_reason}.+?)\s{1,100}:"""
    """server\s{1,100}=\s{1,100}({dest_ip}.+?)\s{1,100}:"""
    """user\s{1,100}=\s{1,100}(\*+|({user}.+?))\s{1,100}:"""
    """user IP\s{1,100}=\s{1,100}({src_ip}[A-Za-z\d.:]{1,2000})"""
    ]
}
```
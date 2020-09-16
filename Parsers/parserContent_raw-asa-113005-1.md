#### Parser Content
```Java
{
Name = raw-asa-113005-1
  Vendor = Cisco
  Product = Cisco 
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy MMM dd HH:mm:ss"
  Conditions = [ "-113005:", "AAA user authentication Rejected :", ": user =", ": reason =" ]
  Fields = [
    """({time}\d+\s+\w+\s+\d+\s+\d+:\d+:\d+)\s+UTC\s+({host}[^\s]+)\s+:\s+({event_code}[^\s]+):\s+({event_name}.+?)\s+:""",
    """reason\s+=\s+({failure_reason}.+?)\s+:"""
    """server\s+=\s+({dest_ip}.+?)\s+:"""
    """user\s+=\s+(\*+|({user}.+?))\s+:"""
    """user IP\s+=\s+({src_ip}[A-Za-z\d.:]+)"""
    ]
}
```
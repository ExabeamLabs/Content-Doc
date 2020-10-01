#### Parser Content
```Java
{
Name = cisco-ftd-file-download
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-303002", "%FTD-", "Retrieved file" ]
  Fields = [
    """({time}\w+ \d+ \d\d\d\d \d\d:\d\d:\d\d)\s+({host}[\w\-.]+)\s*:\s*%FTD""",
    """%FTD\-({priority}\d+)\-({event_code}\d+)""",
    """ from Inside:\s*({src_ip}[A-Fa-f:\d.]+)\/({src_port}\d+)""",
    """ to Outside:\s*({dest_ip}[A-Fa-f:\d.]+)\/({dest_port}\d+)""",
    """user\s+({user}[^\s]+)""",
    """Retrieved file\s+(|({file_path}({file_parent}[^"]*?)[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)))\s+$""",
  ]
}
```
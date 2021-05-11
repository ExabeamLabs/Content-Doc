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
    """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]+)\s{0,100}:\s{0,100}%FTD""",
    """%FTD\-({priority}\d{1,100})\-({event_code}\d{1,100})""",
    """ from Inside:\s{0,100}({src_ip}[A-Fa-f:\d.]+)\/({src_port}\d{1,100})""",
    """ to Outside:\s{0,100}({dest_ip}[A-Fa-f:\d.]+)\/({dest_port}\d{1,100})""",
    """user\s{1,100}({user}[^\s]+)""",
    """Retrieved file\s{1,100}(|({file_path}({file_parent}[^"]*?)[\\\/]*({file_name}[^\\\/"]+?(\.({file_ext}[^\\\/\.\s"]+))?)))\s{1,100}$""",
  ]
}
```
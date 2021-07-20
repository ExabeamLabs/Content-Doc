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
    """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]{1,2000})\s{0,100}:\s{0,100}%FTD""",
    """%FTD\-({priority}\d{1,100})\-({event_code}\d{1,100})""",
    """ from Inside:\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})\/({src_port}\d{1,100})""",
    """ to Outside:\s{0,100}({dest_ip}[A-Fa-f:\d.]{1,2000})\/({dest_port}\d{1,100})""",
    """user\s{1,100}({user}[^\s]{1,2000})""",
    """Retrieved file\s{1,100}(|({file_path}({file_parent}[^"]{0,2000}?)[\\\/]{0,2000}({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^\\\/\.\s"]{1,2000}))?)))\s{1,100}$""",
  ]
}
```
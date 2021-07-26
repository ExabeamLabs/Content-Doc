#### Parser Content
```Java
{
Name = cisco-ftd-process-created-1
  Vendor = Cisco
  Product = Cisco Adaptive Security Appliance
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ "-111009", "%FTD-" ]
  Fields = [
    """({time}\w+ \d{1,100} \d\d\d\d \d\d:\d\d:\d\d)\s{1,100}({host}[\w\-.]{1,2000})\s{0,100}:\s{0,100}%FTD""",
    """%FTD\-({priority}\d{1,100})\-({event_code}\d{1,100})""",
    """User\s{1,100}'({user}[^']{1,2000})'""",
    """({event_name}executed)""",
    """ cmd:\s{0,100}({command_line}.+?)\s{1,100}$""",
  ]
}
```
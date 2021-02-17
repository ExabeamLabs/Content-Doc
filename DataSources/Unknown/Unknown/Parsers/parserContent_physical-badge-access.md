#### Parser Content
```Java
{
Name = physical-badge-access
  Vendor = Unknown
  Product = Unknown
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """ Device: """, """ EventCode: """, """ OPR: """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """Date:\s*({time}\d+\/\d+\/\d\d\d\d\s+\d+:\d+:\d+\s+(AM|PM|am|pm)) Device:\s*({location_door}.+?)\s+EventCode:\s*({outcome}\d+)\s+Name:\s*(|({user_fullname}[^:]*?))\s+OPR:\s*(|({operation}.*?))\s+$""",
  ]
}
```
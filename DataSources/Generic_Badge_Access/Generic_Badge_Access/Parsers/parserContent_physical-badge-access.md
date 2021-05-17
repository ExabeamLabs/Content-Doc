#### Parser Content
```Java
{
Name = physical-badge-access
  Vendor = Generic Badge Access
  Product = Generic Badge Access
  Lms = Direct
  DataType = "physical-access"
  TimeFormat =  "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """ Device: """, """ EventCode: """, """ OPR: """ ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Date:\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm)) Device:\s{0,100}({location_door}.+?)\s{1,100}EventCode:\s{0,100}({outcome}\d{1,100})\s{1,100}Name:\s{0,100}(|({user_fullname}[^:]{0,2000}?))\s{1,100}OPR:\s{0,100}(|({operation}.*?))\s{1,100}$""",
  ]
}
```
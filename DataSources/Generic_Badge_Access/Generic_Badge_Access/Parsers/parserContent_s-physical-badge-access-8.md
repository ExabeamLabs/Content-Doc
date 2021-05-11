#### Parser Content
```Java
{
Name = s-physical-badge-access-8
  Vendor = Generic Badge Access
  Product = Generic Badge Access
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """"BADGE VALID""""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """AckTStamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """Description:\s{0,100}"{0,20}({last_name}[^,"]+),\s{1,100}({first_name}[^,"]+)""",
    """Badge:\s{0,100}"{0,20}({badge_id}[^"]+)""",
    """Class:\s{0,100}"{0,20}({outcome}[^"]+)""",
    """Name:\s{0,100}"{0,20}({location_full}[^"]+)""",
  ]
}
```
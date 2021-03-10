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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """AckTStamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)""",
    """Description:\s*"*({last_name}[^,"]+),\s+({first_name}[^,"]+)""",
    """Badge:\s*"*({badge_id}[^"]+)""",
    """Class:\s*"*({outcome}[^"]+)""",
    """Name:\s*"*({location_full}[^"]+)""",
  ]
}
```
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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """AckTStamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d{1,100})""",
    """Description:\s{0,100}"{0,20}({last_name}[^,"]{1,2000}),\s{1,100}({first_name}[^,"]{1,2000})""",
    """Badge:\s{0,100}"{0,20}({badge_id}[^"]{1,2000})""",
    """Class:\s{0,100}"{0,20}({outcome}[^"]{1,2000})""",
    """Name:\s{0,100}"{0,20}({location_full}[^"]{1,2000})""",
  ]
}
```
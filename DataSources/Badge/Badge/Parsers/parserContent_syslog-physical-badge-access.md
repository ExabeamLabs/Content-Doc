#### Parser Content
```Java
{
Name = syslog-physical-badge-access
    Vendor = Badge
  Product = Badge
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [":0CardAdmitted;","exabeam_raw"]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """:\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100}:\d[^;]{1,2000};({host}[^;\s]{1,2000});""",
      """:\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100}:\d({outcome}[^;]{1,2000});""",
      """:\d{1,100}\.\d{1,100}\.\d{1,100}\.\d{1,100}:\d[^;]{1,2000};[^;]{1,2000};({last_name}[^,]{1,2000}),\s{0,100}({first_name}[^;]{1,2000})""",
      """(?:[^;]{0,2000};){3}({location_door}[^;]{1,2000})?""",
      """(?:[^;]{0,2000};){4}({user}[^;]{1,2000})?""",
      """(?:[^;]{0,2000};){3}(?:[^.]{0,2000}.){3}({location_city}[^.]{1,2000})""",
      """(?:[^;]{0,2000};){3}(?:[^.]{0,2000}.){4}({location_building}[^.]{1,2000})""",
      """(?:[^;]{0,2000};){3}(?:[^.]{0,2000}.){5}({location_door}[^;]{1,2000})"""
    ]
  }
```
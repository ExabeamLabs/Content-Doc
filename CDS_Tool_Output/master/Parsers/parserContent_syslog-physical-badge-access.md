#### Parser Content
```Java
{
Name = syslog-physical-badge-access
    Vendor = Unknown
  Product = Unknown
    Lms = Direct
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [":0CardAdmitted;","exabeam_raw"]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """:\d+\.\d+\.\d+\.\d+:\d[^;]+;({host}[^;\s]+);""",
      """:\d+\.\d+\.\d+\.\d+:\d({outcome}[^;]+);""",
      """:\d+\.\d+\.\d+\.\d+:\d[^;]+;[^;]+;({last_name}[^,]+),\s*({first_name}[^;]+)""",
      """(?:[^;]*;){3}({location_door}[^;]+)?""",
      """(?:[^;]*;){4}({user}[^;]+)?""",
      """(?:[^;]*;){3}(?:[^.]*.){3}({location_city}[^.]+)""",
      """(?:[^;]*;){3}(?:[^.]*.){4}({location_building}[^.]+)""",
      """(?:[^;]*;){3}(?:[^.]*.){5}({location_door}[^;]+)"""
    ]
  }
```
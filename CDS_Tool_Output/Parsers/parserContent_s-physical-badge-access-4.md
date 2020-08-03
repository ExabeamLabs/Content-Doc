#### Parser Content
```Java
{
Name = s-physical-badge-access-4
    Vendor = Unknown
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ "WorkerID=", "PrimarySeatLocation=", "exabeam_raw"]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """WorkerID=({employee_id}\d+)""",
      """FirstName=({first_name}.+?)\s+LastName=""",
      """LastName=({last_name}.+?)\s+WorkerID=""",
      """MessageType=({outcome}.+?)\s+Door=""",
      """Location="+({location_building}[^"]+)""",
      """Door="+({location_door}[^"]+)"""
    ]
  }

  {
    Name = syslog-physical-badge-access
    Vendor = Unknown
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
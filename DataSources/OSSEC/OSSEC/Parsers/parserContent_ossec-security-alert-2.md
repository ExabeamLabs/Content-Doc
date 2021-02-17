#### Parser Content
```Java
{
Name = ossec-security-alert-2
  Vendor = OSSEC
  Product = OSSEC
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ ossec""", """Alert Level:""", """->syscheck; """, """ Location: """, """ classification:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\sAlert Level:\s*({alert_severity}\d+)""",
    """\sRule:\s*({alert_name}[^;]+)""",
    """\sLocation:\s*\(({dest_host}[^\)]+)""",
    """Location:(\s*\([^;]*?\))?\s*(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^;\-]+))""",
    """\s(?i)file\s*'({file_path}({file_parent}[^']*?[\\\/]+)?({file_name}[^'\\\/]+?(\.({file_ext}\w+))?))'""",
    """\d\d:\d\d:\d\d\s*({host}[^\s]+)\s*ossec:""",
    """classification:\s*({alert_type}[^,]+)""",
  ]
}
```
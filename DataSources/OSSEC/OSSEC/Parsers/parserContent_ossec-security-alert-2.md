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
    """\sAlert Level:\s{0,100}({alert_severity}\d{1,100})""",
    """\sRule:\s{0,100}({alert_name}[^;]{1,2000})""",
    """\sLocation:\s{0,100}\(({dest_host}[^\)]{1,2000})""",
    """Location:(\s{0,100}\([^;]{0,2000}?\))?\s{0,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^;\-]{1,2000}))""",
    """\s(?i)file\s{0,100}'({file_path}({file_parent}[^']{0,2000}?[\\\/]{1,2000})?({file_name}[^'\\\/]{1,2000}?(\.({file_ext}\w+))?))'""",
    """\d\d:\d\d:\d\d\s{0,100}({host}[^\s]{1,2000})\s{0,100}ossec:""",
    """classification:\s{0,100}({alert_type}[^,]{1,2000})""",
  ]
}
```
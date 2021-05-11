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
    """\sRule:\s{0,100}({alert_name}[^;]+)""",
    """\sLocation:\s{0,100}\(({dest_host}[^\)]+)""",
    """Location:(\s{0,100}\([^;]*?\))?\s{0,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^;\-]+))""",
    """\s(?i)file\s{0,100}'({file_path}({file_parent}[^']*?[\\\/]+)?({file_name}[^'\\\/]+?(\.({file_ext}\w+))?))'""",
    """\d\d:\d\d:\d\d\s{0,100}({host}[^\s]+)\s{0,100}ossec:""",
    """classification:\s{0,100}({alert_type}[^,]+)""",
  ]
}
```
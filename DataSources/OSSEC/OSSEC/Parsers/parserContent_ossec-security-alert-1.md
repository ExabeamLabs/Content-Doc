#### Parser Content
```Java
{
Name = ossec-security-alert-1
  Vendor = OSSEC
  Product = OSSEC
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ ossec""", """Alert Level:""", """->syscheck; """, """ Location: """ ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d) ({host}[\w.\-]+) ossec """,
    """\sAlert Level:\s{0,100}({alert_severity}\d{1,100})""",
    """\sRule:\s{0,100}({alert_name}[^;]+)""",
    """\sLocation:\s{0,100}\(({dest_host}[^\)]+)""",
    """Location:(\s{0,100}\([^;]*?\))?\s{0,100}(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({dest_host}[^;\-]+))""",
    """\sfor:\s{0,100}'({file_path}({file_parent}[^']*?[\\\/]+)?({file_name}[^'\\\/]+?(\.({file_ext}\w+))?))'""",
    """\sCurrent SHA1:\s{0,100}'({sha1_sum}[^;']+)""",
    """\sCurrent MD5:\s{0,100}'({md5_sum}[^;']+)"""
  ]
}
```
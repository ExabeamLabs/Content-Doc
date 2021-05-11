#### Parser Content
```Java
{
Name = solaris-audit-process
  Vendor = Oracle
  Product = Oracle Solaris
  Lms = Splunk
  DataType = "process-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """from """, """audit.notice""", """ID 702911""","""execve""" ]
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}).[^,]+.[^,]+.({host}[^,]+)""",
    """({event_code}702911)\s({event_name}audit.notice)]\s{0,100}({activity}[^\s]+)""",
    """({outcome}(ok|failed))""",
    """session\s{0,100}({logon_id}\d{1,100})""",
    """by\s{0,100}({user}[^\s]+)""",
    """as\s{0,100}({authentication}[^\s]+)""",
    """\sin\s({src_zone}[^\s]+)""",
    """from\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """obj\s{0,100}(?:({process}({directory}[^\s]*?)(\/+({process_name}[^\/]+?))?))\s{1,100}""",
    """argv\s{0,100}({command_line}[^"]+)"""
  ]
}
```
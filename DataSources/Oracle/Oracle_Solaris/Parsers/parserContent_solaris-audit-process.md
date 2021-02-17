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
    """({time}\d+-\d+-\d+\s\d+:\d+:\d+).[^,]+.[^,]+.({host}[^,]+)""",
    """({event_code}702911)\s({event_name}audit.notice)]\s*({activity}[^\s]+)""",
    """({outcome}(ok|failed))""",
    """session\s*({logon_id}\d+)""",
    """by\s*({user}[^\s]+)""",
    """as\s*({authentication}[^\s]+)""",
    """\sin\s({src_zone}[^\s]+)""",
    """from\s*({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """obj\s*(?:({process}({directory}[^\s]*?)(\/+({process_name}[^\/]+?))?))\s+""",
    """argv\s*({command_line}[^"]+)"""
  ]
}
```
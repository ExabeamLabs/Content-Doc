#### Parser Content
```Java
{
Name = syslog-microsoft-print-activity
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-PrintService[""", """ owned by """, """ was printed on """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}\S+)\sMicrosoft-Windows-PrintService\[""",
    """Microsoft-Windows-PrintService\[[^:]+:\s((NT AUTHORITY\\)|({domain}[^\\]+)\\)?((SYSTEM)|({user}[^:\s]+)):""",
    """EventID ({event_code}\d+)""",
    """\]:\s*({time}\d{4}\-\d\d\-\d\d \d\d:\d\d:\d\d)\s({host}[^\s]+)\s[^\s]+\s({event_code}\d+)\s(({domain}[^\\]+)\\+)?({user}[^\s]+)\s""",
    """\s({activity_1}Document) \d+,""",
    """owned by [^\s]+\s*[^$]*?( on [^\s]+)?({activity_2}[^\s]+?) on ({printer_name}[^$]+?)(\.\s+|\s+through)""",
    """\sDocument \d+,\s+({object}[^$"]+?)\s+owned by"""
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}\S+)) was """,
    """through port (\w+_)?(?:nul|({dest_ip}[A-Fa-f:\d.]+)|\\*({dest_host}[^\s]+?))(_\d+)?:?\.\s+Size in bytes""",
    """Size in bytes:\s*({bytes}\d+)""",
    """Pages printed:\s*({num_pages}\d+)"""
  ]
}
```
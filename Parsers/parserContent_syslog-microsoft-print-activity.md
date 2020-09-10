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
    """\]:\s*({time}\d{4}\-\d\d\-\d\d \d\d:\d\d:\d\d)\s({host}[^\s]+)\s[^\s]+\s({event_code}\d+)\s(({domain}[^\\]+)\\+)?({user}[^\s]+)\s""",
    """\s({activity_1}Document) \d+,""",
    """owned by [^\s]+\s*.*?( on [^\s]+)?({activity_2}.+?) on ({printer_name}.+?)(\.\s+|\s+through)""",
    """\sDocument \d+,\s+({object}.+?) owned by""",
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}.+?)) was """,
    """through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]+)|\\*({dest_host}.+?))(_\d+)?\.\s+""",
    """Size in bytes:\s*({bytes}\d+)""",
    """Pages printed:\s*({num_pages}\d+)"""
  ]
}
```
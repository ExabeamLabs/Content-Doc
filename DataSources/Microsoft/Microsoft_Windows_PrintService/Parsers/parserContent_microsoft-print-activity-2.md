#### Parser Content
```Java
{
Name = microsoft-print-activity-2
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """Microsoft-Windows-PrintService""","""Printing a document""", """rn=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """owned by [^\s]+\s*.*?( on [^\s]+)?({activity_2}.+?) on ({printer_name}.+?)(\.\s+|\s+through)""",
    """owned by ({user}.+?) (to|on) """,
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}.+?)) was """,
    """through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]+)|\\*({dest_host}.+?))\.\s+""",
    """Size in bytes:\s+({bytes}\d+)""",
    """Pages printed:\s+({num_pages}\d+)""",
    """[\[\(]+({access}Read-Only)[\]\)]+""",
    """({event_code}307)""",
    """exabeam_host=({host}[^\s]+)""",
    """Document \d+,\s+({object}.+?)\s*owned by""",
    """\s({time}\w+\s+\d\d\s+\d\d:\d\d:\d\d\s+\d\d\d\d),""",
    """PrintService,({user_sid}\w+-\w+-\w+-\w+-\w+-\w+-\w+-\w+),""",
    """,({host}[^,]+),Printing a document""",
    """({event_name}Printing a document)"""
  ]
  DupFields = ["event_name->activity"]
}
```
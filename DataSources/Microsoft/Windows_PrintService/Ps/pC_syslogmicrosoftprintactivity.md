#### Parser Content
```Java
{
Name = syslog-microsoft-print-activity
  Vendor = Microsoft
  Product = Windows PrintService
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Microsoft-Windows-PrintService[""", """ owned by """, """ was printed on """ ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}\S+)\sMicrosoft-Windows-PrintService\[""",
    """Microsoft-Windows-PrintService\[[^:]{1,2000}:\s((NT AUTHORITY\\)|({domain}[^\\]{1,2000})\\)?((SYSTEM)|({user}[^:\s]{1,2000})):""",
    """EventID ({event_code}\d{1,100})""",
    """\]:\s{0,100}({time}\d{4}\-\d\d\-\d\d \d\d:\d\d:\d\d)\s({host}[^\s]{1,2000})\s[^\s]{1,2000}\s({event_code}\d{1,100})\s(({domain}[^\\]{1,2000})\\+)?({user}[^\s]{1,2000})\s""",
    """\s({activity_1}Document) \d{1,100},""",
    """owned by [^\s]{1,2000}\s{0,100}[^$]{0,2000}?( on [^\s]{1,2000})?({activity_2}[^\s]{1,2000}?) on ({printer_name}[^$]{1,2000}?)(\.\s{1,100}|\s{1,100}through)""",
    """\sDocument \d{1,100},\s{1,100}({object}[^$"]{1,2000}?)\s{1,100}owned by"""
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}\S+)) was """,
    """through port (\w+_)?(?:nul|({dest_ip}[A-Fa-f:\d.]{1,2000})|\\*({dest_host}[^\s]{1,2000}?))(_\d{1,100})?:?\.\s{1,100}Size in bytes""",
    """Size in bytes:\s{0,100}({bytes}\d{1,100})""",
    """Pages printed:\s{0,100}({num_pages}\d{1,100})"""
  ]
}
```
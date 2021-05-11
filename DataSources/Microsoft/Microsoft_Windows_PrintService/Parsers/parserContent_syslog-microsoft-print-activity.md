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
    """EventID ({event_code}\d{1,100})""",
    """\]:\s{0,100}({time}\d{4}\-\d\d\-\d\d \d\d:\d\d:\d\d)\s({host}[^\s]+)\s[^\s]+\s({event_code}\d{1,100})\s(({domain}[^\\]+)\\+)?({user}[^\s]+)\s""",
    """\s({activity_1}Document) \d{1,100}
```
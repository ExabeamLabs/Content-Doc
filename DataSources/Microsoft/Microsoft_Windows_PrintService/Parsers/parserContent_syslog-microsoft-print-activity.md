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
    """Microsoft-Windows-PrintService\[[^:]{1,2000}:\s((NT AUTHORITY\\)|({domain}[^\\]{1,2000})\\)?((SYSTEM)|({user}[^:\s]{1,2000})):""",
    """EventID ({event_code}\d{1,100})""",
    """\]:\s{0,100}({time}\d{4}\-\d\d\-\d\d \d\d:\d\d:\d\d)\s({host}[^\s]{1,2000})\s[^\s]{1,2000}\s({event_code}\d{1,100})\s(({domain}[^\\]{1,2000})\\+)?({user}[^\s]{1,2000})\s""",
    """\s({activity_1}Document) \d{1,100}
```
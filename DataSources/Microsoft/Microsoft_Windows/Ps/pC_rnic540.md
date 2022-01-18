#### Parser Content
```Java
{
Name = r-nic-540
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-540"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "MSWinEventLog", "Successful Network Logon:", ",540,", "Security", "Success Audit", "rsa_sa_log" ]
  Fields = [
    """({event_name}Successful Network Logon)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d{1,100} \d{1,100}:\d{1,100}:\d{1,100} \d{1,100}),""",
    """exabeam_source=({host}[A-Fa-f:\d.]{1,2000})""",
    """\d{2}:\d{2}:\d{2} \d{4

}
```
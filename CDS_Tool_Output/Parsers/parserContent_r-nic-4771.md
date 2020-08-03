#### Parser Content
```Java
{
Name = r-nic-4771
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = RsaSa
  DataType = "windows-4771"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ "Kerberos pre-authentication failed", ",4771,Microsoft-Windows-Security-Auditing", "rsa_sa_log" ]
  Fields = [
    """({event_name}Kerberos pre-authentication failed)""",
    """(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ({time}\w+ \d+ \d+:\d+:\d+ \d+)""",
    """Security,(rn=)?({record_id}[\d]+)""",
    """Failure Audit,({host}[^,]+)""",
    """\d{2}:\d{2}:\d{2} \d{4}
```
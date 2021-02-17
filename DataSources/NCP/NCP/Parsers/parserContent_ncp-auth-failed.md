#### Parser Content
```Java
{
Name = ncp-auth-failed
  Vendor = NCP
  Product = NCP
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """(VPN) PKI: Verification failed!""" ]
  Fields = [
    """<.+?>\w+ \d+ \d\d:\d\d:\d\d ({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\[?({user}[^\s@\[]+)(@({domain}[^\s@\]]+))?\]?\s+\S+\s+\(VPN\) PKI: Verification failed!\s*({failure_reason}[^\.]+)(\.|\s*$)"""
  ]
}
```
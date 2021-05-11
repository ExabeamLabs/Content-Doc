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
    """<.+?>\w+ \d{1,100} \d\d:\d\d:\d\d ({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\[?({user}[^\s@\[]+)(@({domain}[^\s@\]]+))?\]?\s{1,100}\S+\s{1,100}\(VPN\) PKI: Verification failed!\s{0,100}({failure_reason}[^\.]+)(\.|\s{0,100}$)"""
  ]
}
```
#### Parser Content
```Java
{
Name = zebra-wlm-ssh-failed
 Vendor = Extreme Networks
 Product = Zebra wireless LAN management
 Lms = Direct
 DataType = "failed-logon"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = [ """%""", """SYSTEM-3-LOGIN_FAIL:""", """Log-in failed""" ]
 Fields =[
    """({time}\d{1,4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2})""",
    """({time}\w{1,20}\s{1,99}\d{1,2}\s{1,99}\d{1,2}\:\d{1,2}\:\d{1,2})""",
    """\s{1,100}({host}[^\s]{1,2000})\s{1,100}({event_code}%\d{0,20}SYSTEM-3-LOGIN_FAIL):\s{1,100}Log-in ({outcome}failed) for user '({user}[^']{1,2000})'\s{1,100}from '({protocol}[^']{1,2000})\'"""
  ]
  DupFields = ["host->dest_host"]
}
```
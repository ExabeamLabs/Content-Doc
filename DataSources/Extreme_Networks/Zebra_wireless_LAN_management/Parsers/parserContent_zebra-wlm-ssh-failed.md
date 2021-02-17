#### Parser Content
```Java
{
Name = zebra-wlm-ssh-failed
 Vendor = Extreme Networks
 Product = Zebra wireless LAN management
 Lms = Direct
 DataType = "failed-logon"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
 Conditions = [ """%25SYSTEM-3-LOGIN_FAIL:""", """Log-in failed""" ]
 Fields =[
   """({time}\d+-\d+-\d+T\d+:\d+:\d+).\d[^\s]+\s+({host}[^\s]+)\s+({event_code}[^:]+):\s+Log-in ({outcome}failed) for user '({user}[^']+)'\s+from '({protocol}[^']+)*"""
  ]
}
```
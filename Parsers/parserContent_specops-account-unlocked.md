#### Parser Content
```Java
{
Name = specops-account-unlocked
  Vendor = Specops
  Product = Specops Password Reset
  Lms = Splunk
  DataType = "account-unlocked"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """Specops Password Reset""", """<Event xmlns=""", """Unlock Account Succeeded""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{9}Z)'""",
    """({event_name}Unlock Account Succeeded)""",
    """<EventID Qualifiers='0'>({event_code}\d+)</EventID>"""
    """User:\s+'(({target_domain}[^\\\/']+)[\\\/])?({target_user}[^']+)'""",
    """<Computer>({host}[^<]+)</Computer>""",
    """From client:\s+'({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'""",
  ]
}
```
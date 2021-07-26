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
    """<EventID Qualifiers='0'>({event_code}\d{1,100})</EventID>"""
    """User:\s{1,100}'(({target_domain}[^\\\/']{1,2000})[\\\/])?({target_user}[^']{1,2000})'""",
    """<Computer>({host}[^<]{1,2000})</Computer>""",
    """From client:\s{1,100}'({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'""",
  ]
}
```
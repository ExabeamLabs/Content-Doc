#### Parser Content
```Java
{
Name = logrhythm-0365-account-password-change
  Vendor = Microsoft
  Product = Office 365
  Lms = Syslog
  DataType = "password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """SESSID=""", """RESULTCODE=""", """WORKLOAD=""", """COMMAND=Change user password.""", """OBJECT=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """\sTS=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """USER=(Unknown|({user_email}[^@\s]{1,2000}@[^\s\.]{1,2000}?\.[^\s]{1,2000}?)|({user}[^\s@]{1,2000})(@({domain}[^\s]{1,2000}))?)\s{1,100}\w+=""",
    """DOMAIN=(|({domain}[^\s]{1,2000}?))\s{1,100}\w+=""",
    """WORKLOAD=({app}[^=]{1,2000}?)\s{1,100}\w+=""",
    """COMMAND=({event_name}[^=]{1,20000}?)\s{1,100}\w+=""",
    """OBJECT=({target_user}[^=]{1,2000}?)\s{1,100}\w+=""",
    """SIP=({src_ip}[a-fA-F\d:.]{1,2000})""",
    """RESULTCODE=({outcome}[^=]{1,2000}?)\s{1,100}\w+=""",
    """USERAGENT=\s{0,100}(|({user_agent}[^\n]{1,2000}?))\s{0,100}(\w+=|$)"""
  ]
}
```
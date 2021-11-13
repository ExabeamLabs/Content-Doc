#### Parser Content
```Java
{
Name = adfs-500-auth-successful
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """AD FS Auditing""", """500""", """MSWinEventLog""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_code}500)""",
    """AD FS Auditing\s{1,20}({account}[^\s]{1,2000})""",
    """({host}[^\s]{1,2000})\s{1,20}MSWinEventLog""",
    """({time}\w+ \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \d{1,4})\s{1,20}500""",
    """({domain}NT-[^\\]{1,2000})\\({user}[^\s<]{1,200})""",
    """Instance ID:\s{0,100}({iid}[^\s]{1,2000})""",
    """\s({user_email}[^@\s]+@[^\.]{1,2000}\.[^\s]{1,200})\s{1,20}\d{1,2000}""",
    """({outcome}Success Audit)"""
  ]


}
```
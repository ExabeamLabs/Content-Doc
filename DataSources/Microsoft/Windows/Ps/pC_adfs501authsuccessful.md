#### Parser Content
```Java
{
Name = adfs-501-auth-successful
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """AD FS Auditing""", """501""", """MSWinEventLog""", """Caller identity:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_code}501)""",
    """AD FS Auditing\s{1,20}({account}[^\s]{1,2000})""",
    """({host}[^\s]{1,2000})\s{1,20}MSWinEventLog""",
    """({time}\w+ \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \d{1,4})\s{1,20}501""",
    """({domain}NT-[^\\]{1,2000})\\({user}[^\s<]{1,200})""",
    """Instance ID:\s{0,100}({iid}[^\s]{1,2000})""",
    """\s({user_email}[^@\s]+@[^\.]{1,2000}\.[^\s]{1,200})\s{1,20}\d{1,2000}""",
    """({outcome}Success Audit)"""
  ]


}
```
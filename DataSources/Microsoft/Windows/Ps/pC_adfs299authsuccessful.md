#### Parser Content
```Java
{
Name = adfs-299-auth-successful
  Vendor = Microsoft
  Product = Windows
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """AD FS Auditing""", """299""", """MSWinEventLog""", """A token was successfully issued""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({event_code}299)""",
    """AD FS Auditing\s{1,20}({account}[^\s]{1,2000})""",
    """({host}[^\s]{1,2000})\s{1,20}MSWinEventLog""",
    """({time}\w+ \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} \d{1,4})\s{1,20}299""",
    """Instance ID:\s{0,100}({iid}[^\s]{1,2000})""",
    """\s({user_email}[^@\s]+@[^\.]{1,2000}\.[^\s]{1,200})\s{1,20}\d{1,2000}""",
    """({outcome}Success Audit)""",
    """({event_name}A token was successfully issued)"""
  ]


}
```
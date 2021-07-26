#### Parser Content
```Java
{
Name = adfs-auth-failed
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """'AD FS'""", """<EventID>342</EventID>""", """Token validation failed""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)""",
    """<Computer>({host}[^\<]{1,2000})<\/Computer>""",
    """<EventID>({event_code}[^\<]{1,2000})<\/EventID>""",
    """<EventRecordID>({record_id}[^\<]{1,2000})<\/EventRecordID>""",
    """ProcessID='({process_id}[^\']{1,2000})""",
    """ThreadID='({thread_id}[^\']{1,2000})""",
    """UserID='({user_id}[^\']{1,2000})""",
    """<\/Data><Data>({user_email}[^\s]{1,2000}?)\s{0,100}\-({failure_reason}.+?)<\/Data><Data>""",
  ]
}
```
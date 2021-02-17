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
    """<Computer>({host}[^\<]+)<\/Computer>""",
    """<EventID>({event_code}[^\<]+)<\/EventID>""",
    """<EventRecordID>({record_id}[^\<]+)<\/EventRecordID>""",
    """ProcessID='({process_id}[^\']+)""",
    """ThreadID='({thread_id}[^\']+)""",
    """UserID='({user_id}[^\']+)""",
    """<\/Data><Data>({user_email}[^\s]+?)\s*\-({failure_reason}.+?)<\/Data><Data>""",
  ]
}
```
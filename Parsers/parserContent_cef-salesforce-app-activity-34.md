#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-34
  Vendor = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Sales Cloud""", """type\=EmailMessage""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({activity}EmailMessage)""",
    """LastModifiedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """LastModifiedBy\.Username\\=({user_email}[^\s;]+)""",
    """ToAddress\\=({object}[^\s;]+)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """suser=({user_email}[^@\s;]+?@[^@\s;]+)\s*(\w+=|$)""",
    """({app}Sales Cloud)"""
  ]
  DupFields = [ "user_email->user" ]
}
```
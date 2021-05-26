#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-38
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=addedtodelegatedgroup;""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]{1,2000}@({email_domain}[^\s;]{1,2000}))""",
    """Display\\=Added ({object}.+?) to .*?delegated group""",
    """Action\\=({activity}[^;]{1,2000})""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """({app}Sales Cloud)"""
  ]
  DupFields = [ "user_email->user" ]
}
```
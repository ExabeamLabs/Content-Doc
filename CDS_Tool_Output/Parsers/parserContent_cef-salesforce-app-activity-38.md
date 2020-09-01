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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]+@({email_domain}[^\s;]+))""",
    """Display\\=Added ({object}.+?) to .*?delegated group""",
    """Action\\=({activity}[^;]+)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """({app}Sales Cloud)"""
  ]
  DupFields = [ "user_email->user" ]
}
```
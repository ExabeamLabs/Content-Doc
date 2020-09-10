#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-3
  Vendor = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Action\=changedPicklistSort;""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^\s;]+)""",
    """Action\\=({activity}[^;]+)""",
    """Display\\=({additional_info}.+?)\s*(\w+=|$)""",
    """Display\\=Reordered ({object}.+?) picklist""",
    """({app}Sales Cloud)""",
  ]
}
```
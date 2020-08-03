#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-26
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """Sales Cloud""", """|audit-event|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """LastModifiedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^\s;]+)""",
    """suser=(({domain}[^\\\s@;=]+)\\+)?(system|({user}[^\\\=\s;@]+))\s+(\w+=|$)""",
    """suser=({user_email}[^\\\=\s;@]+@[^\\\=\s;@]+)""",
    """Owner\.Name\\=(System|({user_fullname}[^;]+?));""",
    """;Name\\=({object}[^;]+?);""",
    """dproc=({activity}[^;]+?)\s+(\w+=|$)""",
    """Action\\=({activity}[^;]+)""",
    """Display\\=({additional_info}.+?)\s*(\w+=|$)""",
    """({app}Sales Cloud)""",
  ]
}
```
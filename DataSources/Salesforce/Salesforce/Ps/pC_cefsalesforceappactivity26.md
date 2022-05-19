#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-26
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName =Sales Cloud""", """|audit-event|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """LastModifiedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]{1,2000}@({email_domain}[^\s;]{1,2000}))""",
    """suser=(({domain}[^\\\s@;=]{1,2000})\\+)?(system|({user}[^\\\=\s;@]{1,2000}))\s{1,100}(\w+=|$)""",
    """suser=({user_email}[^\\\=\s;@]{1,2000}@[^\\\=\s;@]{1,2000})""",
    """Owner\.Name\\=(System|({user_fullname}[^;]{1,2000}?));""",
    """;Name\\=({object}[^;]{1,2000}?);""",
    """dproc=({activity}[^;]{1,2000}?)\s{1,100}(\w+=|$)""",
    """Action\\=({activity}[^;]{1,2000})""",
    """Display\\=({additional_info}.+?)\s{0,100}(\w+=|$)""",
    """({app}Sales Cloud)""",
  ]


}
```
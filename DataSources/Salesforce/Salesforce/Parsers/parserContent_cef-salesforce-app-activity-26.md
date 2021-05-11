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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",  
    """CreatedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """LastModifiedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """CreatedBy\.Username\\=({user_email}[^@]+@({email_domain}[^\s;]+))""",
    """suser=(({domain}[^\\\s@;=]+)\\+)?(system|({user}[^\\\=\s;@]+))\s{1,100}(\w+=|$)""",
    """suser=({user_email}[^\\\=\s;@]+@[^\\\=\s;@]+)""",
    """Owner\.Name\\=(System|({user_fullname}[^;]+?));""",
    """;Name\\=({object}[^;]+?);""",
    """dproc=({activity}[^;]+?)\s{1,100}(\w+=|$)""",
    """Action\\=({activity}[^;]+)""",
    """Display\\=({additional_info}.+?)\s{0,100}(\w+=|$)""",
    """({app}Sales Cloud)""",
  ]
}
```
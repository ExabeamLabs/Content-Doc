#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-32
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """|resource-deleted|""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) \S+ Skyformation -""",	
    """LastModifiedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
    """LastModifiedBy\.Username\\=({user_email}[^@]{1,2000}@({email_domain}[^\s;]{1,2000}))""",
    """\|SkyFormation Cloud Apps Security\|([^\|]{0,2000}\|){2}({activity}[^\|]{1,2000}?)\|""",
    """suser=({user}.+?)\s{1,100}(\w+=|$)""",
    """suser=({user_email}[^@\s;]{1,2000}?@[^@\s;]{1,2000})\s{0,100}(\w+=|$)""",
    """duser=({target_user}[^\\\s]{1,2000})""",
    """fname=({object}.+?)\s{1,100}(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """({app}Sales Cloud)""",
  ]
  DupFields = [ "object->resource" ]


}
```
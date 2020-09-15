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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}\S+) Skyformation -""",	
    """LastModifiedDate\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""
    """LastModifiedBy\.Username\\=({user_email}[^@]+@({email_domain}[^\s;]+))""",
    """\|SkyFormation Cloud Apps Security\|([^\|]*\|){2}({activity}[^\|]+?)\|""",
    """suser=({user}.+?)\s+(\w+=|$)""",
    """suser=({user_email}[^@\s;]+?@[^@\s;]+)\s*(\w+=|$)""",
    """duser=({target_user}[^\\\s]+)""",
    """fname=({object}.+?)\s+(\w+=|$)""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """({app}Sales Cloud)""",
  ]
  DupFields = [ "object->resource" ]
}
```
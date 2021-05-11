#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-41
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """|resource-property-updated|""", """Sales Cloud""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) \S+ Skyformation -""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
    """\Wsuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s;]+?@[^@\s;]+)\s{0,100}(\w+=|$)""",
    """\Wfname=({object}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs1=\{({new_value}[^\}]+)""",
    """\Wcs2=\{({old_value}[^\}]+)""",
    """\WdestinationServiceName=({app}.+?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "object->resource" ]
}
```
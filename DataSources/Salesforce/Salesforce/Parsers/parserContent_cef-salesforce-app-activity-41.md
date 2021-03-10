#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-41
  Vendor = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """|resource-property-updated|""", """Sales Cloud""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}\S+) Skyformation -""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
    """\Wsuser=({user}.+?)\s+(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s;]+?@[^@\s;]+)\s*(\w+=|$)""",
    """\Wfname=({object}.+?)\s+(\w+=|$)""",
    """\Wcs1=\{({new_value}[^\}]+)""",
    """\Wcs2=\{({old_value}[^\}]+)""",
    """\WdestinationServiceName=({app}.+?)\s*(\w+=|$)""",
  ]
  DupFields = [ "object->resource" ]
}
```
#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-41
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|resource-property-updated|""", """destinationServiceName =Sales Cloud""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) \S+ """,
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """\Wsuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s;]{1,2000}?@[^@\s;]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wfname=({object}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs1=\{({new_value}[^\}]{1,2000})""",
    """\Wcs2=\{({old_value}[^\}]{1,2000})""",
    """\WdestinationServiceName =({app}.+?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "object->resource" ]


}
```
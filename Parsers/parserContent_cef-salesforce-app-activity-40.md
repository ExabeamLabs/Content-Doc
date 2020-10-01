#### Parser Content
```Java
{
Name = cef-salesforce-app-activity-40
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """|password-reset|""", """Google Apps""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) ({host}\S+) Skyformation -""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wsuser=({user}.+?)\s+(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s;]+?@[^@\s;]+)\s*(\w+=|$)""",
    """\Wduser=({target_user}[^\\\s]+)""",
    """\WdestinationServiceName=({app}.+?)\s*(\w+=|$)""",
  ]
}
```
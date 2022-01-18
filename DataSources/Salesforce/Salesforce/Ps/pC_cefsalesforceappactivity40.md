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
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ) \S+ Skyformation -""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s;]{1,2000}?@[^@\s;]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wduser=({target_user}[^\\\s]{1,2000})""",
    """\WdestinationServiceName =({app}.+?)\s{0,100}(\w+=|$)""",
  ]


}
```
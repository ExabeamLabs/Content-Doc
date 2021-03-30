#### Parser Content
```Java
{
Name = cef-microsoft-failed-app-login
  DataType = "failed-app-login"
  Conditions = [ """CEF:""", """destinationServiceName=Office 365""", """description":"Failed log on """ ]
  Fields = ${MSParserTemplates.cef-azure-app-activity-1.Fields}[
    """"description":"Failed log on \(({failure_reason}[^\)]+)""",
    """\Wext_failedUserData_userName=(|({user_email}[^=@]+?@[^=]+?)|({user}.+?))(\s+\w+=|\s*$)"""
  ]
}
cef-azure-app-activity-1 = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w.\-]+)""",
    """\Wdvc=({host}\S+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wact=({activity}.+?)\s+(\w+=|$)""",
    """\Wrt=({time}\d+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) \S+ Skyformation""",
    """\Wduser=(anonymous|({user_email}[^@=]+@[^@=]+?)|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wsuser=(anonymous|({user_email}[^@=]+@[^@=]+?)|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wsuid=(anonymous|({user_email}[^@=]+@[^@=]+?)|({user}.+?))(\s+\w+=|\s*$)""",
    """\Woutcome=({outcome}.+?)\s+(\w+=|$)""",
    """CEF:([^\|]*\|){2}({app}[^\|]+)""",
    """\WdestinationServiceName=({app}.+?)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wshost=(|--|({src_host}.+?))(\s+\w+=|\s*$)""",
    """"description":"({additional_info}[^"]+?)\s*"""",
  ]

```
#### Parser Content
```Java
{
Name = o365-teams-activity-1
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """MicrosoftTeams""", """Operation""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"CreationTime\\*"+:[\s\\]*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """destinationServiceName=({app}.+?)\s*deviceInboundInterface""",
    """Workload"*:"*({app}[^"]+)""",
    """Workload"*:\s*"*({app}[^"]+)"*\}""",
    """ObjectId"*:\s*"*((?i)(Unknown)|({object}[^"]+))"*""",
    """Operation"*:\s*"*({activity}[^"]+)"*""",
    """UserKey"*:\s*"*({user_email}[^@"]+@({email_domain}[^"]+))"*""",
    """UserId"*:\s*"*({user_email}[^@"]+@({email_domain}[^"]+))"*""",
    """"ClientIP\\*"+:[\s\\]*"+(::1|\[?({src_ip}[a-fA-F\d.:]+))""",
    ]
}
```
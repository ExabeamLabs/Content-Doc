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
    """"CreationTime\\*"{1,20}:[\s\\]*"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """destinationServiceName=({app}.+?)\s{0,100}deviceInboundInterface""",
    """Workload"{0,20}:"{0,20}({app}[^"]+)""",
    """Workload"{0,20}:\s{0,100}"{0,20}({app}[^"]+)"{0,20}\}""",
    """ObjectId"{0,20}:\s{0,100}"{0,20}((?i)(Unknown)|({object}[^"]+))"{0,20}""",
    """Operation"{0,20}:\s{0,100}"{0,20}({activity}[^"]+)"{0,20}""",
    """UserKey"{0,20}:\s{0,100}"{0,20}({user_email}[^@"]+@({email_domain}[^"]+))"{0,20}""",
    """UserId"{0,20}:\s{0,100}"{0,20}({user_email}[^@"]+@({email_domain}[^"]+))"{0,20}""",
    """"ClientIP\\*"{1,20}:[\s\\]*"{1,20}(::1|\[?({src_ip}[a-fA-F\d.:]+))""",
    """src-account-name":"({account_name}[^"]+)""",
    ]
}
```
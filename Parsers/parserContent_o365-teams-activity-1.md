#### Parser Content
```Java
{
Name = o365-teams-activity-1
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Workload""", """MicrosoftTeams""", """Operation""" ]
  Fields = [
    """"*CreationTime"*:\s*"*({time}\d+-\d+-\d+T\d+:\d+:\d+)"*""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+({host}[\w\-.]+)\s+Skyformation""",
    """destinationServiceName=({app}.*?)\s*deviceInboundInterface""",
    """Workload"*:"*({app}[^"]+)""",
    """Workload"*:\s*"*({app}[^"]+)"*\}""",
    """ObjectId"*:\s*"*({object}[^"]+)"*""",
    """Operation"*:\s*"*({activity}[^"]+)"*""",
    """UserId"*:\s*"*({user_email}[^@]+@({email_domain}[^"]+))"*"""
    ]
}
```
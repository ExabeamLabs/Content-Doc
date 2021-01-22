#### Parser Content
```Java
{
Name = o365-teams-activity-1
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """MicrosoftTeams""", """Operation""" ]
  Fields = [
    """"*CreationTime"*:\s*"*({time}\d+-\d+-\d+T\d+:\d+:\d+)"*""",
    """destinationServiceName=({app}.*?)\s*deviceInboundInterface""",
    """Workload"*:"*({app}[^"]+)""",
    """Workload"*:\s*"*({app}[^"]+)"*\}""",
    """ObjectId"*:\s*"*({object}[^"]+)"*""",
    """Operation"*:\s*"*({activity}[^"]+)"*""",
    """UserId"*:\s*"*({user_email}[^"]+)"*"""
    ]
}
```
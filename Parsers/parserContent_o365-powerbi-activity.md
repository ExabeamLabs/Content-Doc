#### Parser Content
```Java
{
Name = o365-powerbi-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Workload""", """PowerBI""", """WorkspaceId""" ]
  Fields = [
    """"*CreationTime"*:\s*"*({time}\d+-\d+-\d+T\d+:\d+:\d+)"*""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)\s+({host}[\w\-.]+)\s+Skyformation""",
    """destinationServiceName=({app}.*?)\s*deviceInboundInterface""",
    """Workload"*:\s*"*({app}[^"]+)"*""",
    """ObjectId"*:\s*"*({object}[^"]+)"*""",
    """Operation"*:\s*"*({activity}[^"]+)"*""",
    """UserAgent"*:\s*"*(?:-|Mozilla\/.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))"""
    """UserId"*:\s*"*({user_email}[^@]+({email_domain}[^"]+))"*""",
    """"userPrincipalName":"({user_email}[^"@\s]+@({email_domain}[^"@\s]+))"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"ClientIP"+:"+({src_ip}[A-Fa-f:\d.]+)""",
    """UserAgent"*:\s*"*({user_agent}[^"]+)"*,""",
    """DatasetName"*:\s*"*({data_set_name}[^"]+)""",
    """Workload"*:\s*"*({resource}[^"]+)"*"""
    ]
}
```
#### Parser Content
```Java
{
Name = o365-powerbi-activity
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """Workload""", """PowerBI""", """WorkspaceId""" ]
  Fields = [
    """"{0,20}CreationTime"{0,20}:\s{0,100}"{0,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"{0,20}""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)\s{1,100}[\w\-.]+\s{1,100}Skyformation""",
    """destinationServiceName=({app}.*?)\s{0,100}deviceInboundInterface""",
    """Workload"{0,20}:\s{0,100}"{0,20}({app}[^"]+)"{0,20}""",
    """ObjectId"{0,20}:\s{0,100}"{0,20}({object}[^"]+)"{0,20}""",
    """Operation"{0,20}:\s{0,100}"{0,20}({activity}[^"]+)"{0,20}""",
    """UserAgent"{0,20}:\s{0,100}"{0,20}(?:-|Mozilla\/.+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))"""
    """UserId"{0,20}:\s{0,100}"{0,20}({user_email}[^@]+@({email_domain}[^"]+))"{0,20}""",
    """"userPrincipalName":"({user_email}[^"@\s]+@({email_domain}[^"@\s]+))"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
    """"ClientIP"{1,20}:"{1,20}({src_ip}[A-Fa-f:\d.]+)""",
    """UserAgent"{0,20}:\s{0,100}"{0,20}({user_agent}[^"]+)"{0,20}
```
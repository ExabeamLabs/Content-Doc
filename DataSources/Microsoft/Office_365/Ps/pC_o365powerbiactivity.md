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
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """"{0,20}CreationTime"{0,20}:\s{0,100}"{0,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"{0,20}""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)\s{1,100}[\w\-.]{1,2000}\s{1,100}""",
    """destinationServiceName =({app}.*?)\s{0,100}deviceInboundInterface""",
    """Workload"{0,20}:\s{0,100}"{0,20}({app}[^"]{1,2000})"{0,20}""",
    """ObjectId"{0,20}:\s{0,100}"{0,20}({object}[^"]{1,2000})"{0,20}""",
    """Operation"{0,20}:\s{0,100}"{0,20}({activity}[^"]{1,2000})"{0,20}""",
    """UserId"{0,20}:\s{0,100}"{0,20}({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"{0,20}""",
    """"userPrincipalName":"({user_email}[^"@\s]{1,2000}@({email_domain}[^"@\s]{1,2000}))"""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"ClientIP"{1,20}:"{1,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """UserAgent"{0,20}:\s{0,100}"{0,20}({user_agent}[^"]{1,2000})"{0,20

}
```
#### Parser Content
```Java
{
Name = o365-teams-app-login
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload""", """"Operation":"TeamsSessionStarted"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"CreationTime":"({time}\d+\-\d+\-\d+T\d+:\d+:\d+)"""",
    """"Workload":"({app}[^"]+)"""",
    """"UserId":"({user_email}[^@]+@({email_domain}[^"]+))"""",
    """\Wsuser=({user_email}[^@]+@({email_domain}[^\s+?]))\s+(\w+=|$)""",
    """"ObjectId":"(Unknown|({os}[^"\(\)]+[^\s\(\)]))"""
  ]
}
```
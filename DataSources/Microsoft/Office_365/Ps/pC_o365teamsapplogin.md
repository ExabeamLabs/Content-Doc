#### Parser Content
```Java
{
Name = o365-teams-app-login
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload""", """"Operation":"TeamsSessionStarted"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"CreationTime":"({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})"""",
    """"Workload":"({app}[^"]{1,2000})"""",
    """"UserId":"({user_email}[^@]{1,2000}@({email_domain}[^"]{1,2000}))"""",
    """\Wsuser=({user_email}[^@]{1,2000}@({email_domain}[^\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """"ObjectId":"(Unknown|({os}[^"\(\)]{1,2000}[^\s\(\)]))"""
  ]


}
```
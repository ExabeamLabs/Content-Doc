#### Parser Content
```Java
{
Name = o365-teams-activity-1
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """Workload""", """"MicrosoftTeams"""", """Operation""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"CreationTime\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """destinationServiceName =({app}[^=]{1,2000}?)\s{0,100}deviceInboundInterface""",
    """Workload"{0,20}:"{0,20}({app}[^"]{1,2000})""",
    """Workload"{0,20}:\s{0,100}"{0,20}({app}[^"]{1,2000})"{0,20}\}""",
    """ObjectId"{0,20}:\s{0,100}"{0,20}((?i)(Unknown)|({object}[^"]{1,2000}))"{0,20}""",
    """"Operation"{0,20}:\s{0,100}"{0,20}({activity}[^"]{1,2000})"{0,20}""",
    """UserKey"{0,20}:\s{0,100}"{0,20}({user_email}[^@"]{1,2000}@({email_domain}[^"]{1,2000}))"{0,20}""",
    """UserId"{0,20}:\s{0,100}"{0,20}({user_email}[^@"]{1,2000}@({email_domain}[^"]{1,2000}))"{0,20}""",
    """"ClientIP\\{0,20}"{1,20}:[\s\\]{0,2000}"{1,20}\[?(::ffff:)?({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))"""",
    """src-account-name":"({account_name}[^"]{1,2000})""",
    """UserAgent","Value":"({user_agent}[^"]{1,2000})""",
    ]


}
```
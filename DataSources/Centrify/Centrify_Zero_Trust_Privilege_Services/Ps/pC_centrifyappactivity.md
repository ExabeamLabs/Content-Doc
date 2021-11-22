#### Parser Content
```Java
{
Name = centrify-app-activity
  Vendor = Centrify
  Product = Centrify Zero Trust Privilege Services
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""destinationServiceName =Centrify""", """Centrify""", """"EventType":"""" ]
  Fields = [
    """exabeam_time=({time}\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"NormalizedUser":"(({user_email}[^@"]{1,2000}@({email_domain}[^\."]{1,2000}\.[^"]{1,2000})")|(({user}[^"@]+)(@({domain}[^"]+)?)))""",
    """"EventType":"({activity}[^"]{1,2000})"""
    """destinationServiceName =({app}[^\s]{1,2000})""",
    """"CredentialType":"({object}[^"]{1,2000})""",
    """"AuthoritySource":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"ComputerName":"({dest_host}[^"]{1,2000})""",
    """"EventMessage":"({additional_info}[^"]{1,2000})""",
    """"FailReason":"({failure_reason}[^"]{1,2000})""",
    """"AuthMethod":"(?:None|({auth_method}[^"]{1,2000}))""",
    """"RequestUserAgent":"({user_agent}[^"]{1,2000})""",
    """"FromIPAddress":"({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """"RequestUserAgent":"(?:-|Mozilla\/[^=]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """src=({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """cat=({event_name}[^\s]{1,2000})""",
        ]


}
```
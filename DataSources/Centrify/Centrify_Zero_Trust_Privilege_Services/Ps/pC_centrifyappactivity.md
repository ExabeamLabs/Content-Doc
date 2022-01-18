#### Parser Content
```Java
{
Name = centrify-app-activity
  Vendor = Centrify
  Product = Centrify Zero Trust Privilege Services
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = ["""destinationServiceName =""", """Centrify""", """CEF:""", """|skyformation|""", """|SkyFormation Cloud Apps Security|""" ]
  Fields = [
    """end=({time}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """suser=(?:system|({user}[^\s]{1,2000}))""",
    """suser=({user_email}[^@\s]{1,2000}@({email_domain}[^\s@]{1,2000}))""",
    """CEF:([^\|]{0,2000}\|){5}\s{0,100}({activity}[^\|]{0,2000}?)\s{0,100}\|""",
    """destinationServiceName =({app}[^\s]{1,2000})""",
    """"CredentialType":"({object}[^"]{1,2000})""",
    """"AuthoritySource":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"ComputerName":"({dest_host}[^"]{1,2000})""",
    """sourceServiceName =({service_name}[^\s]{1,2000})""",
    """msg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """reason=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
    """"EventType":"({log_type}[^"]{1,2000})""",
    """"AuthMethod":"(?:None|({authentication_method}[^"]{1,2000}))""",
    """"RequestUserAgent":"({user_agent}[^"]{1,2000})""",
    """src=({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """cat=({event_name}[^\s]{1,2000})""",
    """"RequestUserAgent":"(?:-|Mozilla\/[^=]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
        ]


}
```
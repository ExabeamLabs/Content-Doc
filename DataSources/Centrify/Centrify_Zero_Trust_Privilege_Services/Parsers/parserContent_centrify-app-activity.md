#### Parser Content
```Java
{
Name = centrify-app-activity
  Vendor = Centrify
  Product = Centrify Zero Trust Privilege Services
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = ["""destinationServiceName=""", """Centrify""", """CEF:""", """|skyformation|""", """|SkyFormation Cloud Apps Security|""" ]
  Fields = [
    """end=({time}\d{1,100})""",
    """exabeam_host=({host}[\w.\-]+)""",
    """suser=(?:system|({user}[^\s]+))""",
    """suser=({user_email}[^@\s]+@({email_domain}[^\s@]+))""",
    """CEF:([^\|]*\|){5}\s{0,100}({activity}[^\|]*?)\s{0,100}\|""",
    """destinationServiceName=({app}[^\s]+)""",
    """"CredentialType":"({object}[^"]+)""",
    """"AuthoritySource":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"ComputerName":"({dest_host}[^"]+)""",
    """sourceServiceName=({service_name}[^\s]+)""",
    """msg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """reason=({failure_reason}.+?)\s{1,100}(\w+=|$)""",
    """"EventType":"({log_type}[^"]+)""",
    """"AuthMethod":"(?:None|({authentication_method}[^"]+))""",
    """"RequestUserAgent":"({user_agent}[^"]+)""",
    """src=({src_ip}[A-Fa-f\d:.]+)""",
    """cat=({event_name}[^\s]+)""",
    """"RequestUserAgent":"(?:-|Mozilla\/[^=]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
        ]
}
```
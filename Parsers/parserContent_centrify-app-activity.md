#### Parser Content
```Java
{
Name = centrify-app-activity
  Vendor = Centrify
  Product = Centrify
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = ["""destinationServiceName=""", """Centrify""", """CEF:""", """|skyformation|""", """|SkyFormation Cloud Apps Security|""" ]
  Fields = [
    """end=({time}\d+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """suser=(?:system|({user}[^\s]+))""",
    """suser=({user_email}[^@\s]+@({email_domain}[^\s@]+))""",
    """CEF:([^\|]*\|){5}\s*({activity}[^\|]*?)\s*\|""",
    """destinationServiceName=({app}[^\s]+)""",
    """"CredentialType":"({object}[^"]+)""",
    """"AuthoritySource":"({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"ComputerName":"({dest_host}[^"]+)""",
    """sourceServiceName=({service_name}[^\s]+)""",
    """msg=({additional_info}.+?)\s+(\w+=|$)""",
    """reason=({failure_reason}.+?)\s+(\w+=|$)""",
    """"EventType":"({log_type}[^"]+)""",
    """"AuthMethod":"(?:None|({authentication_method}[^"]+))""",
    """"RequestUserAgent":"({user_agent}[^"]+)""",
    """src=({src_ip}[A-Fa-f\d:.]+)""",
    """cat=({event_name}[^\s]+)""",
    """"RequestUserAgent":"(?:-|Mozilla\/[^=]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
        ]
}
```
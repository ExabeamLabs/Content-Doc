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
{  
  Name = s-onguard-physical-badge-access-2
  Vendor = Onguard
  Product = Onguard
  Lms = Splunk
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"readerdesc"""", """"segmentname"""", """"panelname"""", """"badgekey"""", """"event_time_utc"""", """"changedate"""" ]
  Fields = [
    """"host"+:\s*"+({host}[^"]+)"""",
    """"event_time_utc"+:"+({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d)""",
    """"lastname"+:\s*"+({last_name}[^"]+)"""",
    """"firstname"+:\s*"+({first_name}[^"]+)"""",
    """"cardnum"+:({card_num}\d+)""",
    """"readerdesc"+:\s*"+({location_door}[^"]+)"""",
    """"devid"+:({devid}\d+)""",
    """"panelname"+:\s*"+({location_building}[^"]+)"""",
    """"emp_id"+:({employee_id}\d+)""",
    """"badgekey":({badge_id}\d+)"""
  ]
}
```
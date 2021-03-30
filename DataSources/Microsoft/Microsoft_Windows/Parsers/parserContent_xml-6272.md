#### Parser Content
```Java
{
Name = xml-6272
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>6272<""", """'SubjectUserName'>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """<Computer>({host}[\w\-.]+)""",
    """({event_code}6272)""",
    """<EventRecordID>({record_id}[^<]+)""",
    """'SubjectUserSid'>({user_sid}[^"\s<]+)<""",
    """'SubjectUserName'>(?:({user_type}host)/)?(({domain}[^\\\s"<]+)\\+)?({user}[^"\\\s<]+)<""",
    """'SubjectDomainName'>({domain}[^"\s<]+)<""",
    """'NASIdentifier'>(?:-|({location}[\w\-.]+))""",
    """'CallingStationID'>(?:-|({src_mac}[^\<]+))""",
    """'AuthenticationProvider'>(?:-|({auth_server}[^\<]+))""",
    """'FullyQualifiedSubjectMachineName'>(?:-|({user_type}.+?))(\/[^\/\s]+)?<""",
    """'NASIPv6Address'>({dest_ip}[a-fA-F:\d.]+)""",
    """'NASIPv4Address'>({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """'EAPType'>(?:-|({auth_type}[^\<]+))""",
    """'QuarantineState'>(?:-|({access_type}[^\<]+))""",
  ]
}
```
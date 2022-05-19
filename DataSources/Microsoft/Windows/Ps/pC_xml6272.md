#### Parser Content
```Java
{
Name = xml-6272
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-nac-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>6272<""", """'SubjectUserName'>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """<Computer>({host}[\w\-.]{1,2000})""",
    """({event_code}6272)""",
    """<EventRecordID>({record_id}[^<]{1,2000})""",
    """'SubjectUserSid'>({user_sid}[^"\s<]{1,2000})<""",
    """'SubjectUserName'>(?:({user_type}host)/)?(({domain}[^\\\s"<]{1,2000})\\+)?({user}[^"\\\s<]{1,2000})<""",
    """'SubjectDomainName'>({domain}[^"\s<]{1,2000})<""",
    """'NASIdentifier'>(?:-|({location}[\w\-.]{1,2000}))""",
    """'CallingStationID'>(?:-|({src_mac}[^\<]{1,2000}))""",
    """'AuthenticationProvider'>(?:-|({auth_server}[^\<]{1,2000}))""",
    """'FullyQualifiedSubjectMachineName'>(?:-|({user_type}.+?))(\/[^\/\s]{1,2000})?<""",
    """'NASIPv6Address'>({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """'NASIPv4Address'>({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """'EAPType'>(?:-|({auth_type}[^\<]{1,2000}))""",
    """'QuarantineState'>(?:-|({access_type}[^\<]{1,2000}))""",
  ]


}
```
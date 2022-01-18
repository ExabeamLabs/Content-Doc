#### Parser Content
```Java
{
Name = microsoft-nps-6273
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = Direct
  DataType = "windows-nac-failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>6273</EventID>""", """<Message>Network Policy Server denied access to a user""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """<Computer>({host}[\w\-.]{1,2000})""",
    """({event_code}6273)""",
    """'SubjectUserName'>(?:({user_type}host)/)?(({domain}[^\\]{1,2000})\\+)?({user}[^<]{1,2000})""",
    """'SubjectDomainName'>(?:-|({domain}[^\s\<]{1,2000}))""",
    """'FullyQualifiedSubjectUserName'>(({domain}[^\\]{1,2000})\\+)?(?:-|({user}[^\s\\\<]{1,2000}))""",
    """'NASIdentifier'>(?:-|({location}[\w\-.]{1,2000}))""",
    """'AuthenticationProvider'>(?:-|({auth_server}[^\<]{1,2000}))""",
    """'FullyQualifiedSubjectMachineName'>(?:-|({user_type}.+?))(\/[^\/\s]{1,2000})?<""",
    """'NASIPv6Address'>({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """'NASIPv4Address'>({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """'Reason'>({reason}[^<]{1,2000})"""
  ]


}
```
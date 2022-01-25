#### Parser Content
```Java
{
Name = xml-5143
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>5143""", """>A network share object was modified""", """<Data Name ='SubjectUserSid'"""]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)'""",
    """<Computer>({host}[\w\-.]{1,20000})<""",
    """<EventID>({event_code}5143)""",
    """<Data Name ='SubjectUserSid'>({user_sid}[^<]{1,2000})<""",
    """<Data Name ='SubjectUserName'>({user}[^<]{1,2000})<""",
    """<Data Name ='SubjectDomainName'>({domain}[^<]{1,2000})<""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^<]{1,2000})<""",
    """<Data Name ='ObjectType'>({file_type}[^<]{1,2000})<""",
    """<Data Name ='ShareName'>[\\\*]{0,2000}({share_name}[^<]{1,2000})<""",
    """<Data Name ='ShareLocalPath'>[\\\?]{0,2000}({share_path}(({d_parent}[^@]{1,2000}?)\\)?(|({d_name}[^\\]{1,2000}?)))<""",
    """<Message>({event_name}A network share object was modified)"""
  ]


}
```
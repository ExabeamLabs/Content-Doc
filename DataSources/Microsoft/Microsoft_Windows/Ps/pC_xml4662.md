#### Parser Content
```Java
{
Name = xml-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<EventID>4662<""" ]
  Fields = [
    """({event_name}An operation was performed on an object)""",
    """<EventID>({event_code}\d{1,100})""",
    """<TimeCreated SystemTime(\\)?='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]{1,2000})""",
    """<Data Name(\\)?='SubjectUserSid'>({user_sid}[^<]{1,2000})""",
    """<Data Name(\\)?='SubjectUserName'>(-|({user}[^<]{1,2000}))""",
    """<Data Name(\\)?='SubjectDomainName'>(-|({domain}[^<]{1,2000}))""",
    """<Data Name(\\)?='SubjectLogonId'>({logon_id}[^<]{1,2000})""",
    """<Data Name(\\)?='ObjectServer'>({object_class}[^<]{1,2000})""",
    """<Data Name(\\)?='ObjectType'>({object_type}[^<]{1,2000})""",
    """<Data Name(\\)?='ObjectName'>({object}[^<]{1,2000})""",
    """<Data Name(\\)?='OperationType'>({activity}[^<]{1,2000})""",
    """<Data Name(\\)?='Properties'>(-|({properties}[^<]{1,2000}?))\s{0,100}<""",
    """<Keyword>({outcome}[^<]{1,2000})<"""
  ]


}
```
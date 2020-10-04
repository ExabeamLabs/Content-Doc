#### Parser Content
```Java
{
Name = xml-4662-jp
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """<EventID>4662<""", """オブジェクトに対して操作が実行されました。""" ]
  Fields = [
    """({event_name}オブジェクトに対して操作が実行されました。)""",
    """({event_code}4662)""",
    """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s+""",
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d+Z'/>""",
    """Computer(Name)?\s*\\*"?(=|:|>)\s*"*({host}[\w\.-]+)(\s|,|"|</Computer>|$)""",
    """<EventRecordID>({record_id}[^<]+)""",
    """'SubjectUserSid'>({user_sid}[^"\s<]+)<""",
    """'SubjectUserName'>({user}[^"\s<]+)<""",
    """'SubjectDomainName'>({domain}[^"\s<]+)<""",
    """'SubjectLogonId'>({logon_id}[^"\s<]+)<""",
    """'ObjectServer'>({object_class}[^<]+)<""",
    """'ObjectType'>\%?\{?({activity_type}[^<>\{\}]+)""",
    """'ObjectName'>\%?\{?({object}[^<>\{\}]+)""",
    """'OperationType'>({activity}[^<]+)<""",
    """'HandleId'>({handle_id}[^<]+)<""",
    """'Properties'>[\-\\r\\n\s]*({properties}[^<]+?)[\-\\r\\n\s]*<""",
  ]
}
```
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
    """({time}\w+ \d\d \d\d:\d\d:\d\d \d\d\d\d)\s{1,100}""",
    """<TimeCreated SystemTime='({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d{1,100}Z'/>""",
    """Computer(Name)?\s{0,100}\\*"?(=|:|>)\s{0,100}"{0,20}({host}[\w\.-]{1,2000})(\s|,|"|</Computer>|$)""",
    """<EventRecordID>({record_id}[^<]{1,2000})""",
    """'SubjectUserSid'>({user_sid}[^"\s<]{1,2000})<""",
    """'SubjectUserName'>({user}[^"\s<]{1,2000})<""",
    """'SubjectDomainName'>({domain}[^"\s<]{1,2000})<""",
    """'SubjectLogonId'>({logon_id}[^"\s<]{1,2000})<""",
    """'ObjectServer'>({object_class}[^<]{1,2000})<""",
    """'ObjectType'>\%?\{?({object_type}[^<>\{\}]{1,2000})""",
    """'ObjectName'>\%?\{?({object}[^<>\{\}]{1,2000})""",
    """'OperationType'>({activity}[^<]{1,2000})<""",
    """'HandleId'>({handle_id}[^<]{1,2000})<""",
    """'Properties'>[\-\\r\\n\s]{0,2000}({properties}[^<]{1,2000}?)[\-\\r\\n\s]{0,2000}<""",
  ]


}
```
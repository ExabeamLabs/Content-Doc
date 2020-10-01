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
    """<EventID>({event_code}\d+)""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Computer>({host}[^<]+)""",
    """<Data Name='SubjectUserSid'>({user_sid}[^<]+)""",
    """<Data Name='SubjectUserName'>({user}[^<]+)""",
    """<Data Name='SubjectDomainName'>({domain}[^<]+)""",
    """<Data Name='SubjectLogonId'>({logon_id}[^<]+)""",
    """<Data Name='ObjectServer'>({object_class}[^<]+)""",
    """<Data Name='ObjectType'>({action}[^<]+)""",
    """<Data Name='ObjectName'>({object}[^<]+)""",
    """<Data Name='OperationType'>({activity}[^<]+)""",
    """<Data Name='Properties'>({properties}[^<]+?)\s*<""",
  ]
}
```
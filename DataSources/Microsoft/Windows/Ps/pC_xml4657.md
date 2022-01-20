#### Parser Content
```Java
{
Name = xml-4657
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "registry-write"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>4657</EventID>""", """<EventRecordID>""", ]
  Fields = [
    """<EventID>({event_code}\d{1,100})</EventID>""",
    """<Keywords>({outcome}[^\<]{1,2000})</Keywords>""",
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)'""",
    """<EventRecordID>({record_id}[^\<]{1,2000})</EventRecordID>""",
    """<Computer>({host}[^\<]{1,2000})</Computer>""",
    """<Data Name ='SubjectUserSid'>({user_sid}[^\<]{1,2000})</Data>""",
    """<Data Name ='SubjectUserName'>({user}[^\<]{1,2000})</Data>""",
    """<Data Name ='SubjectDomainName'>({domain}[^\<]{1,2000})</Data>""",
    """<Data Name ='SubjectLogonId'>({logon_id}[^\<]{1,2000})</Data>""",
    """<Data Name ='HandleId'>({object_id}[^\<]{1,2000})</Data>""",
    """<Data Name ='OperationType'>({activity}[^\<]{1,2000})</Data>""",
    """<Data Name ='NewValueType'>(-|({registry_details_type}[^\<]{1,2000}))</Data>""",
    """<Data Name ='NewValue'>(-|({registry_details}[^\<]{1,2000}))</Data>""",
    """<Data Name ='ProcessId'>({process_id}[^\<]{1,2000})</Data>""",
    """<Data Name ='ProcessName'>({process}({process_directory}(?:(\w+:)?[^:]{1,2000})?[\\\/])?({process_name}.+?))</Data>""",
    """<Data Name ='ObjectName'>({registry_key}[^\<]{1,2000})<\/Data>""",
    """<Data Name ='ObjectValueName'>({registry_value}[^\<]{1,2000})<\/Data>"""
  ]


}
```
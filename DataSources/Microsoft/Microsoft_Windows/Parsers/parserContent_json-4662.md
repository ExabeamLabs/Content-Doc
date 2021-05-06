#### Parser Content
```Java
{
Name = json-4662
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "object-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""An operation was performed on an object""", """"EventID":4662""", """"OperationType":""""]
  Fields = [
    """"Hostname":"({host}[^"]+)""",
    """({event_name}An operation was performed on an object)""",
    """({event_code}4662)""",
    """"EventTime":"?({time}[^",]+)""",
    """"EventTime":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"SubjectUserSid":"({user_sid}[^"]+)"""",
    """"SubjectUserName":"({user}[^"]+)"""",
    """"SubjectDomainName":"({domain}[^"]+)"""",
    """"ObjectName":"({object}[^"]+)"""",
    """"ObjectServer":"({object_class}[^"]+)"""",
    """"ObjectType":"({activity_type}[^"]+)"""",
    """"LogonID":"({logon_id}[^"]+)"""",
    """"OperationType":"({activity}[^"]+)"""",
    """"Properties":"(-|({properties}[^"]+))"""",
    """"AdditionalInfo":"(?:-|({additional_info}[^"]+))""""
  ]
}
```
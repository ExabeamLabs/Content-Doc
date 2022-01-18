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
    """"Hostname":"({host}[^"]{1,2000})""",
    """({event_name}An operation was performed on an object)""",
    """({event_code}4662)""",
    """"EventTime":"?({time}[^",]{1,2000})""",
    """"EventTime":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
    """"SubjectUserName":"({user}[^"]{1,2000})"""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"ObjectName":"({object}[^"]{1,2000})"""",
    """"ObjectServer":"({object_class}[^"]{1,2000})"""",
    """"ObjectType":"({object_type}[^"]{1,2000})"""",
    """"LogonID":"({logon_id}[^"]{1,2000})"""",
    """"OperationType":"({activity}[^"]{1,2000})"""",
    """"Properties":"(-|({properties}[^"]{1,2000}))"""",
    """"AdditionalInfo":"(?:-|({additional_info}[^"]{1,2000}))""""
  ]


}
```
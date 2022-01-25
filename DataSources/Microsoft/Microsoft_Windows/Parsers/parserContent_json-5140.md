#### Parser Content
```Java
{
Name = json-5140
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "share-access"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""A network share object was accessed""", """"EventID":5140"""]
    Fields = [
      """({event_name}A network share object was accessed)""",
      """({event_code}5140)""",
      """"Hostname":"({host}[^"]{1,2000})"""",
      """"EventTime":({time}\d{1,100})""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
      """"SubjectUserName":"({user}[^"]{1,2000})"""",
      """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
      """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
      """"ObjectType":"({file_type}[^"]{1,2000})"""",
      """IpAddress":"({src_ip}[A-Fa-f\d:.]{1,2000})""",
      """"IpPort":"({src_port}\d{1,100})"""",
      """"ShareName":"[\\*]{0,2000}({share_name}[^"]{1,2000})"""",
      """({accesses}Read)""",
      """"ShareLocalPath":"[\\?]{0,2000}(({share_path}(({d_parent}.+?)\\)?(|({d_name}[^\\]{1,2000}?)))\\?)","""
      """"ProcessID":({process_id}\d{1,100}),""",
      """"RecordNumber":({record_id}\d{1,100}),""",
      """"Category":"({service}[^"]{1,2000})",""",
    ]
    DupFields = ["host->dest_host"]
  }
```
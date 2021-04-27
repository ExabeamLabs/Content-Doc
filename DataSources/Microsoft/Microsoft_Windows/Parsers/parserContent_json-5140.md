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
      """"Hostname":"({host}[^"]+)"""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"SubjectUserSid":"({user_sid}[^"]+)"""",
      """"SubjectUserName":"({user}[^"]+)"""",
      """"SubjectDomainName":"({domain}[^"]+)"""",
      """"SubjectLogonId":"({logon_id}[^"]+)"""",
      """"ObjectType":"({file_type}[^"]+)"""",
      """IpAddress":"({src_ip}[A-Fa-f\d:.]+)""",
      """"IpPort":"({src_port}\d+)"""",
      """"ShareName":"[\\*]*({share_name}[^"]+)"""",
      """({accesses}Read)""",
      """"ShareLocalPath":"[\\?]*(({share_path}(({d_parent}.+?)\\)?(|({d_name}[^\\]+?)))\\?)","""
      """"ProcessID":({process_id}\d+),""",
      """"RecordNumber":({record_id}\d+),""",
      """"Category":"({service}[^"]+)",""",
    ]
    DupFields = ["host->dest_host"]
  }
```
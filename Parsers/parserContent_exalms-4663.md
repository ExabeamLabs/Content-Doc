#### Parser Content
```Java
{
Name = exalms-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":4663,""","An attempt was made to access an object",""""@timestamp"""" ]
  Fields = [
    """({event_name}An attempt was made to access an object)""",
    """"@timestamp"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"computer_name"\s*:\s*"({host}.+?)"""",
    """"record_number"\s*:\s*"({record_id}\d+)""",
    """({event_code}4663)""",
    """"SubjectUserSid"\s*:\s*"({user_sid}[^"]+)""",
    """"SubjectUserName"\s*:\s*"({user}[^"]+)""",
    """"SubjectDomainName"\s*:\s*"({domain}[^"]+)""",
    """"SubjectLogonId"\s*:\s*"({logon_id}[^"]+)""",
    """"ObjectType"\s*:\s*"({file_type}[^"]+)""",
    """"ObjectName"\s*:\s*"({file_path}[^"]+)""",
    """"ObjectName"\s*:\s*"[^"]+\\({file_name}[^".]+(\.({file_ext}[^"\\.]+))?)"""",
    """"ObjectName"\s*:\s*"(?:({file_parent}[^"]+?)\\+[^"\\]+)"""",
    """"ProcessName"\s*:\s*"({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """"AccessList"\s*:\s*"({accesses}.+?)"""",
    """Access Request Information:[rnt\\]*Accesses:[rnt\\]*({accesses}.*)[rnt\\]*Access Mask:[rnt\\]*({access_mask}.+?)\s*("|$)""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```
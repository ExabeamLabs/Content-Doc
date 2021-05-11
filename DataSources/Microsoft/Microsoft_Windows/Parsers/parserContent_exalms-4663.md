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
    """"@timestamp"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """"record_number"\s{0,100}:\s{0,100}"({record_id}\d{1,100})""",
    """({event_code}4663)""",
    """"SubjectUserSid"\s{0,100}:\s{0,100}"({user_sid}[^"]+)""",
    """"SubjectUserName"\s{0,100}:\s{0,100}"({user}[^"]+)""",
    """"SubjectDomainName"\s{0,100}:\s{0,100}"({domain}[^"]+)""",
    """"SubjectLogonId"\s{0,100}:\s{0,100}"({logon_id}[^"]+)""",
    """"ObjectType"\s{0,100}:\s{0,100}"({file_type}[^"]+)""",
    """"ObjectName"\s{0,100}:\s{0,100}"({file_path}[^"]+)""",
    """"ObjectName"\s{0,100}:\s{0,100}"[^"]+\\({file_name}[^".]+(\.({file_ext}[^"\\.]+))?)"""",
    """"ObjectName"\s{0,100}:\s{0,100}"(?:({file_parent}[^"]+?)\\+[^"\\]+)"""",
    """"ProcessName"\s{0,100}:\s{0,100}"({process}({directory}(?:[^"]+)?[\\\/])?({process_name}[^\\\/"]+))"""",
    """"AccessList"\s{0,100}:\s{0,100}"({accesses}.+?)"""",
    """Access Request Information:[rnt\\]*Accesses:[rnt\\]*({accesses}.*)[rnt\\]*Access Mask:[rnt\\]*({access_mask}.+?)\s{0,100}("|$)""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```
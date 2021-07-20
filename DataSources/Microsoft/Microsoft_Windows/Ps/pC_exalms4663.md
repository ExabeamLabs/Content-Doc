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
    """"SubjectUserSid"\s{0,100}:\s{0,100}"({user_sid}[^"]{1,2000})""",
    """"SubjectUserName"\s{0,100}:\s{0,100}"({user}[^"]{1,2000})""",
    """"SubjectDomainName"\s{0,100}:\s{0,100}"({domain}[^"]{1,2000})""",
    """"SubjectLogonId"\s{0,100}:\s{0,100}"({logon_id}[^"]{1,2000})""",
    """"ObjectType"\s{0,100}:\s{0,100}"({file_type}[^"]{1,2000})""",
    """"ObjectName"\s{0,100}:\s{0,100}"({file_path}[^"]{1,2000})""",
    """"ObjectName"\s{0,100}:\s{0,100}"[^"]{1,2000}\\({file_name}[^".]{1,2000}(\.({file_ext}[^"\\.]{1,2000}))?)"""",
    """"ObjectName"\s{0,100}:\s{0,100}"(?:({file_parent}[^"]{1,2000}?)\\+[^"\\]{1,2000})"""",
    """"ProcessName"\s{0,100}:\s{0,100}"({process}({directory}(?:[^"]{1,2000})?[\\\/])?({process_name}[^\\\/"]{1,2000}))"""",
    """"AccessList"\s{0,100}:\s{0,100}"({accesses}.+?)"""",
    """Access Request Information:[rnt\\]{0,2000}Accesses:[rnt\\]{0,2000}({accesses}.*)[rnt\\]{0,2000}Access Mask:[rnt\\]{0,2000}({access_mask}.+?)\s{0,100}("|$)""",
  ]
  DupFields = [ "host->dest_host","directory->process_directory" ]
}
```
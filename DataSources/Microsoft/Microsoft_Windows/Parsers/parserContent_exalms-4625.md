#### Parser Content
```Java
{
Name = exalms-4625
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":4625""", """An account failed to log on.""", """"@timestamp"""" ]
  Fields = [
    """({event_name}An account failed to log on)""",
    """"@timestamp"\s*:\s*"({time}.+?)"""",
    """"computer_name"\s*:\s*"({host}.+?)"""",
    """"event_id"\s*:\s*({event_code}\d+)""",
    """"record_number"\s*:\s*"({record_id}\d+)""",
    """"(SubjectUserSid)"\s*:\s*"(-|({caller_user_sid}.+?))\s*"""",
    """"(SubjectUserName)"\s*:\s*"(-|({caller_user}.+?))\s*"""",
    """"(SubjectDomainName)"\s*:\s*"(-|({caller_domain}.+?))\s*"""",
    """"(LogonType)"\s*:\s*"({logon_type}.+?)\s*"""",
    """"(TargetUserSid)"\s*:\s*"({user_sid}.+?)\s*"""",
    """"(TargetUserName)"\s*:\s*"(-|({user}.+?))\s*"""",
    """"(TargetDomainName)"\s*:\s*"(-|({domain}.+?))\s*"""",
    """"(SubStatus)"\s*:\s*"(-|({result_code}.+?))\s*"""",
    """"(WorkstationName|workstation_name)"\s*:\s*"(-|({src_host_windows}.+?))\s*"""",
    """"(WorkstationName|workstation_name)"\s*:\s*"(-|({src_host}[^"]+)).*Source Network Address:(\\t)*-\\""",
    """"(LogonProcessName)"\s*:\s*"(-|({auth_process}.+?))\s*"""",
    """"(AuthenticationPackageName|authentication_package)"\s*:\s*"(-|({auth_package}.+?))\s*"""",
    """"(IpAddress|source_ip)"\s*:\s*"(-|({src_ip}.+?))\s*"""",
    """"(failure_reason)"\s*:\s*"(-|({failure_reason}.+?))\s*"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```
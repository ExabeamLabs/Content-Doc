#### Parser Content
```Java
{
Name = exalms-4625
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "windows-failed-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"event_id":4625""", """An account failed to log on.""", """"@timestamp"""" ]
  Fields = [
    """({event_name}An account failed to log on)""",
    """"@timestamp"\s{0,100}:\s{0,100}"({time}.+?)"""",
    """"(?:winlog\.)?computer_name"\s{0,100}:\s{0,100}"({host}.+?)"""",
    """"event_id"\s{0,100}:\s{0,100}({event_code}\d{1,100})""",
    """"record_number"\s{0,100}:\s{0,100}"({record_id}\d{1,100})""",
    """"(SubjectUserSid)"\s{0,100}:\s{0,100}"(-|({caller_user_sid}.+?))\s{0,100}"""",
    """"(SubjectUserName)"\s{0,100}:\s{0,100}"(-|({caller_user}.+?))\s{0,100}"""",
    """"(SubjectDomainName)"\s{0,100}:\s{0,100}"(-|({caller_domain}.+?))\s{0,100}"""",
    """"(LogonType)"\s{0,100}:\s{0,100}"({logon_type}.+?)\s{0,100}"""",
    """"(TargetUserSid)"\s{0,100}:\s{0,100}"({user_sid}.+?)\s{0,100}"""",
    """"(TargetUserName)"\s{0,100}:\s{0,100}"(-|({user}.+?))\s{0,100}"""",
    """"(TargetDomainName)"\s{0,100}:\s{0,100}"(-|({domain}.+?))\s{0,100}"""",
    """"(SubStatus)"\s{0,100}:\s{0,100}"(-|({result_code}.+?))\s{0,100}"""",
    """"(WorkstationName|workstation_name)"\s{0,100}:\s{0,100}"(-|({src_host_windows}.+?))\s{0,100}"""",
    """"(WorkstationName|workstation_name)"\s{0,100}:\s{0,100}"(-|({src_host}[^"]{1,2000})).*Source Network Address:(\\t)*-\\""",
    """"(LogonProcessName)"\s{0,100}:\s{0,100}"(-|({auth_process}.+?))\s{0,100}"""",
    """"(AuthenticationPackageName|authentication_package)"\s{0,100}:\s{0,100}"(-|({auth_package}.+?))\s{0,100}"""",
    """"(IpAddress|source_ip)"\s{0,100}:\s{0,100}"(-|({src_ip}.+?))\s{0,100}"""",
    """"(failure_reason)"\s{0,100}:\s{0,100}"(-|({failure_reason}.+?))\s{0,100}"""",
  ]
  DupFields = [ "host->dest_host" ]


}
```
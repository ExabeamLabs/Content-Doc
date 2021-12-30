#### Parser Content
```Java
{
Name = json-4625
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""4625""", """"FailureReason":""", """"EventID":"""]
    Fields = [
      """({event_name}An account failed to log on)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """"(Hostname|MachineName)":"({host}[^"]{0,2000})""",
      """({event_code}4625)""",
      """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
      """"SubjectUserName":"(?:-|({caller_user}[^"]{1,2000}))""",
      """"SubjectDomainName":"(?:-|({caller_domain}[^"]{1,2000}))""",
      """"LogonType":"({logon_type}[^"]{1,2000})""",
      """"TargetUserName":"({user}[^"]{1,2000})""",
      """"TargetDomainName":"({domain}[^."]{1,2000})""",
      """"SubStatus":"({result_code}[^"]{1,2000})""",
      """"WorkstationName":"({src_host_windows}[^"]{1,2000})""",
      """"LogonProcessName":"({auth_process}[^."]{1,2000}?)\s{0,100}"""",
      """"AuthenticationPackageName":"({auth_package}[^"]{1,2000})""",
      """"IpAddress":"(?:-|({src_ip}[^"]{1,2000}))"""
      """"KeyLength":"({key_length}[^"]{1,2000})""",
      """"SubjectUserSid":"({subject_sid}[^"]{1,2000})"""
    ]
    DupFields = ["host->dest_host"]
  

}
```
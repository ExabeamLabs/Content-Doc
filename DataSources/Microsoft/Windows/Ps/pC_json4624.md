#### Parser Content
```Java
{
Name = json-4624
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""4624""", """"AuthenticationPackageName":""""]
    Fields = [
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]{1,2000}\s""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"TimeCreated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"@timestamp"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)""",
      """"Computer":"({host}[^"]{1,2000})""",
      """({event_name}An account was successfully logged on)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """EventTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)"""",
      """"(Hostname|MachineName|hostname)":"({host}[^"]{0,2000})""",
      """({event_code}4624)""",
      """"LogonType":"?({logon_type}[^",]{1,2000})""",
      """"TargetUserName":"({user}[^"]{0,2000})""",
      """"TargetDomainName":"({domain}[^"]{0,2000})""",
      """"ProcessName":"(?:-|({process}[^"]{0,2000}))""",
      """"IpAddress":"(?:-|({src_ip}[^"]{0,2000}))""",
      """"hostip":"(?:-|({dest_ip}[^"]{0,2000}))""",
      """"LogonProcessName":"({auth_process}.+?)\s{0,100}"""",
      """"AuthenticationPackageName":"({auth_package}[^"]{0,2000})""",
      """"TargetLogonId":"({logon_id}[^"]{0,2000})""",
      """"TargetUserSid":"({user_sid}[^"]{0,2000})""",
      """Workstation Name:((\\)[rnt])*\s{0,100}(|([A-Fa-f:\d.]{1,2000}|-|({src_host_windows}[^\\\s]{1,2000}?))\s{0,100}((\\)[rnt])*)?Source""",
      """"WorkstationName":"(?:|[A-Fa-f:\d.]{1,2000}|-|({src_host_windows}[^"]{1,2000}))"""",
      """"KeyLength":"?({key_length}\d{1,2000})"?,""",
      """"SubjectUserSid":"({subject_sid}[^"]{1,2000})""",
      """"Process":"(-|({process_name}[^"]{1,2000}))""""
    ]
    DupFields = ["host->dest_host"]
  

}
```
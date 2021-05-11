#### Parser Content
```Java
{
Name = json-4624
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-4624"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = ["""4624""", """"AuthenticationPackageName":""""]
    Fields = [
      """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s[^\s]+\sSkyformation""",
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"TimeCreated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"@timestamp"{0,20}:"{0,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)""",
      """"Computer":"({host}[^"]+)""",
      """({event_name}An account was successfully logged on)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s{0,100}({time}\d{1,100})""",
      """"timestamp":\s{0,100}({time}\d{1,100})""",
      """"(Hostname|MachineName|hostname)":"({host}[^"]*)""",
      """({event_code}4624)""",
      """"LogonType":"?({logon_type}[^",]+)""",
      """"TargetUserName":"({user}[^"]*)""",
      """"TargetDomainName":"({domain}[^"]*)""",
      """"ProcessName":"(?:-|({process}[^"]*))""",
      """"IpAddress":"(?:-|({src_ip}[^"]*))""",
      """"hostip":"(?:-|({dest_ip}[^"]*))""",
      """"LogonProcessName":"({auth_process}.+?)\s{0,100}"""",
      """"AuthenticationPackageName":"({auth_package}[^"]*)""",
      """"TargetLogonId":"({logon_id}[^"]*)""",
      """"TargetUserSid":"({user_sid}[^"]*)""",
      """Workstation Name:((\\)[rnt])*\s{0,100}(|([A-Fa-f:\d.]+|-|({src_host_windows}[^\\\s]+?))\s{0,100}((\\)[rnt])*)?Source""",
      """"WorkstationName":"(?:|[A-Fa-f:\d.]+|-|({src_host_windows}[^"]+))"""",
      """"KeyLength":"({key_length}[^"]+)""",
      """"SubjectUserSid":"({subject_sid}[^"]+)"""
    ]
    DupFields = ["host->dest_host"]
  }
```
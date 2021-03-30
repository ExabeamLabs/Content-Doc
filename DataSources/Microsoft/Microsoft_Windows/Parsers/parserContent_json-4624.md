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
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"Computer":"({host}[^"]+)""",
      """({event_name}An account was successfully logged on)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s*({time}\d+)""",
      """"timestamp":\s*({time}\d+)""",
      """"(Hostname|MachineName)":"({host}[^"]*)""",
      """({event_code}4624)""",
      """"LogonType":"?({logon_type}[^",]+)""",
      """"TargetUserName":"({user}[^"]*)""",
      """"TargetDomainName":"({domain}[^"]*)""",
      """"ProcessName":"(?:-|({process}[^"]*))""",
      """"IpAddress":"(?:-|({src_ip}[^"]*))""",
      """"hostip":"(?:-|({dest_ip}[^"]*))""",
      """"LogonProcessName":"({auth_process}[^"]*)""",
      """"AuthenticationPackageName":"({auth_package}[^"]*)""",
      """"TargetLogonId":"({logon_id}[^"]*)""",
      """"TargetUserSid":"({user_sid}[^"]*)""",
      """Workstation Name:((\\)[rnt])*(([A-Fa-f:\d.]+|-|({src_host_windows}[^\\]+))((\\)[rnt])*)?Source""",
      """"WorkstationName":"(?:|[A-Fa-f:\d.]+|-|({src_host_windows}[^"]+))"""",
      """SubjectUserName":"({account}[^"]+)""",
    ]
    DupFields = ["host->dest_host"]
  }
```
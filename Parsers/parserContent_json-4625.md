#### Parser Content
```Java
{
Name = json-4625
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Direct
    DataType = "windows-failed-logon"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""4625""", """"FailureReason":"""]
    Fields = [
      """({event_name}An account failed to log on)""",
      """"EventTime":"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"EventReceivedTime":\s*({time}\d+)""",
      """"timestamp":\s*({time}\d+)""",
      """"(Hostname|MachineName)":"({host}[^"]*)""",
      """({event_code}4625)""",
      """"SubjectUserSid":"({user_sid}[^"]+)""",
      """"SubjectUserName":"(?:-|({caller_user}[^"]+))""",
      """"SubjectDomainName":"(?:-|({caller_domain}[^"]+))""",
      """"LogonType":"({logon_type}[^"]+)""",
      """"TargetUserName":"({user}[^"]+)""",
      """"TargetDomainName":"({domain}[^."]+)""",
      """"SubStatus":"({result_code}[^"]+)""",
      """"WorkstationName":"({src_host_windows}[^"]+)""",
      """"LogonProcessName":"({auth_process}[^."]+?)\s*"""",
      """"AuthenticationPackageName":"({auth_package}[^"]+)""",
      """"IpAddress":"(?:-|({src_ip}[^"]+))"""
    ]
    DupFields = ["host->dest_host"]
  }
```
#### Parser Content
```Java
{
Name = syslog-json-4663
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-4663"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"EventID":4663""",""""SourceModuleType":""" ]
  Fields = [  
    """({event_name}An attempt was made to access an object)""",
    """"EventTime":({time}\d{1,100})""",
    """"EventTime":\s{0,100}"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"""",
    """"Hostname":"({host}[^."]*)""",
    """({event_code}4663)""",
    """"SubjectUserSid":"({user_sid}[^"]+)""",
    """"SubjectUserName":"({user}[^"]+)""",
    """"SubjectDomainName":"({domain}[^"]+)""",
    """"SubjectLogonId":"({logon_id}[^"]+)""",
    """"ObjectType":"({file_type}[^"]+)""",
    """"ObjectName":"({file_path}[^"]+)""",
    """"ObjectName"{1,20}:".*\\({file_name}(?:[^\\:]+(?=\.))({file_ext}\.[^\\:\s]+)?|[^\\:\s]+)"{1,20}
```
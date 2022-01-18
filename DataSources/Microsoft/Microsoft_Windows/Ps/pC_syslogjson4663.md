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
    """"Hostname":"({host}[^."]{0,2000})""",
    """({event_code}4663)""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})""",
    """"SubjectUserName":"({user}[^"]{1,2000})""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})""",
    """"ObjectType":"({file_type}[^"]{1,2000})""",
    """"ObjectName":"({file_path}[^"]{1,2000})""",
    """"ObjectName"{1,20}:".*\\({file_name}(?:[^\\:]{1,2000}(?=\.))({file_ext}\.[^\\:\s]{1,2000})?|[^\\:\s]{1,2000})"{1,20

}
```
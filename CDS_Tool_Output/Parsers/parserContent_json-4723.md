#### Parser Content
```Java
{
Name = json-4723
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Direct
  DataType = "windows-password-change"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"TargetAccount":"""", """"EventID":"4723"""", """An attempt was made to change""" ]
  Fields = [
    """({event_name}An attempt was made to change an account's password)""",
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"Computer":"({host}[\w\-.]+)""",
    """"Account":"(({domain}[^\\\s"]+)\\+)?({user}[^\\\s"]+)""",
    """"TargetAccount":"(({target_domain}[^\\\s"]+)\\+)?({target_user}[^\\\s"]+)""",
    """"SubjectUserSid":"({user_sid}[^\s"]+)""",
    """"SubjectLogonId":"({logon_id}[^\s"]+)""",
    """"TargetSid":"({target_user_sid}[^\s"]+)""",
  ]
}
```
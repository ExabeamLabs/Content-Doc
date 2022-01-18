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
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"Computer":"({host}[\w\-.]{1,2000})""",
    """"Account":"(({domain}[^\\\s"]{1,2000})\\+)?({user}[^\\\s"]{1,2000})""",
    """"TargetAccount":"(({target_domain}[^\\\s"]{1,2000})\\+)?({target_user}[^\\\s"]{1,2000})""",
    """"SubjectUserSid":"({user_sid}[^\s"]{1,2000})""",
    """"SubjectLogonId":"({logon_id}[^\s"]{1,2000})""",
    """"TargetSid":"({target_user_sid}[^\s"]{1,2000})""",
  ]


}
```
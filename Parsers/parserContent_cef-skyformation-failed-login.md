#### Parser Content
```Java
{
Name = cef-skyformation-failed-login
  Vendor = Cloud Application
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Skyformation|""", """|login-failed|""" ]
  Fields = [
    """\Wend=({time}\d+)""",
    """"+created_at"+:"+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",    
    """"time"\s*:\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\ssuser=({user}[^@\s]+)\s+(\w+=|$)""",
    """\ssuser=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
    """\ssuser=.*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s+""",
    """"+created_by"+:\{.+?"+name"+:"+({user_fullname}[^\"]+)"+""",
    """"+source"+:\{.+?"+name"+:"+({user_fullname}[^\"]+)"+""",
    """"failureReason":"({failure_reason}[^\"]+)"""",
    """\sreason=({failure_reason}.+?)(\s+\w+=|\s*$)""",
    """(\||\s)requestClientApplication=({app}.+?)(\s+\w+=|\s*$)""",
  ]
  DupFields = ["app->event_subtype"]
}
```
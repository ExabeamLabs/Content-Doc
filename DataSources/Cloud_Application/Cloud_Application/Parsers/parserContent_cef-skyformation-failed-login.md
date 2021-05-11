#### Parser Content
```Java
{
Name = cef-skyformation-failed-login
  Vendor = Cloud Application
  Product = Cloud Application
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Skyformation|""", """|login-failed|""" ]
  Fields = [
    """\Wend=({time}\d{1,100})""",
    """"{1,20}created_at"{1,20}:"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",    
    """"time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]+)""",
    """\ssrc=({src_ip}[^\s]+)""",
    """\ssuser=({user}[^@\s]+)\s{1,100}(\w+=|$)""",
    """\ssuser=({user_email}[^\s@]+@[^\s@]+)\s{1,100}(\w+=|$)""",
    """\ssuser=.*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{1,100}""",
    """"{1,20}created_by"{1,20}:\{.+?"{1,20}name"{1,20}:"{1,20}({user_fullname}[^\"]+)"{1,20}""",
    """"{1,20}source"{1,20}:\{.+?"{1,20}name"{1,20}:"{1,20}({user_fullname}[^\"]+)"{1,20}""",
    """"failureReason":"({failure_reason}[^\"]+)"""",
    """\sreason=({failure_reason}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """(\||\s)requestClientApplication=({app}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]
  DupFields = ["app->event_subtype"]
}
```
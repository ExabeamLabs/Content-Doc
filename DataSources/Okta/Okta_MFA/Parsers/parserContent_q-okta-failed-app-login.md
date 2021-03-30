#### Parser Content
```Java
{
Name = q-okta-failed-app-login
    Vendor = Okta
    Product = Okta MFA
    Lms = QRadar
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"Sign-in Failed""", """,published"""", """,action"""" ]
    Fields=[
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\Wpublished"\s*:\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\WipAddress"\s*:\s*"({src_ip}[\da-fA-F\.:]+)""",
    """\Wmessage"\s*:\s*"({failure_reason}[^",]+)""",
    """"targets"\s*:\s*\[\{.*?\WdisplayName"\s*:\s*"({user_fullname}[^",]+)""",
    """"targets"\s*:\s*\[\{.*?\Wlogin"\s*:\s*"({user_email}[^",]+)""",
    """({app}Okta)""",
    """"actors":\[\{[^\]\}]*?"id":"({user_agent}.+?),displayName":""",
    """"actors":\[\{[^\]\}]*?displayName":"({browser}\w+)""",
    """"id"\s*:\s*"[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```
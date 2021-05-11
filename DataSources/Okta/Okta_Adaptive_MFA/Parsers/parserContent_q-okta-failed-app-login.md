#### Parser Content
```Java
{
Name = q-okta-failed-app-login
    Vendor = Okta
    Product = Okta Adaptive MFA
    Lms = QRadar
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """"Sign-in Failed""", """,published"""", """,action"""" ]
    Fields=[
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """\Wpublished"\s{0,100}:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\WipAddress"\s{0,100}:\s{0,100}"({src_ip}[\da-fA-F\.:]+)""",
    """\Wmessage"\s{0,100}:\s{0,100}"({failure_reason}[^",]+)""",
    """"targets"\s{0,100}:\s{0,100}\[\{.*?\WdisplayName"\s{0,100}:\s{0,100}"({user_fullname}[^",]+)""",
    """"targets"\s{0,100}:\s{0,100}\[\{.*?\Wlogin"\s{0,100}:\s{0,100}"({user_email}[^",]+)""",
    """({app}Okta)""",
    """"actors":\[\{[^\]\}]*?"id":"({user_agent}.+?),displayName":""",
    """"actors":\[\{[^\]\}]*?displayName":"({browser}\w+)""",
    """"id"\s{0,100}:\s{0,100}"[^"]+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+"""",
  ]
  DupFields = [ "host->dest_host" ]
}
```
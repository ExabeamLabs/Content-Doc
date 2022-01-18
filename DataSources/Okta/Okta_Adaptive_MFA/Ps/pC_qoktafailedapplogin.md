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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\Wpublished"\s{0,100}:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d)""",
    """\WipAddress"\s{0,100}:\s{0,100}"({src_ip}[\da-fA-F\.:]{1,2000})""",
    """\Wmessage"\s{0,100}:\s{0,100}"({failure_reason}[^",]{1,2000})""",
    """"targets"\s{0,100}:\s{0,100}\[\{.*?\WdisplayName"\s{0,100}:\s{0,100}"({user_fullname}[^",]{1,2000})""",
    """"targets"\s{0,100}:\s{0,100}\[\{.*?\Wlogin"\s{0,100}:\s{0,100}"({user_email}[^",]{1,2000})""",
    """({app}Okta)""",
    """"actors":\[\{[^\]\}]{0,2000}?"id":"({user_agent}.+?),displayName":""",
    """"actors":\[\{[^\]\}]{0,2000}?displayName":"({browser}\w+)""",
    """"id"\s{0,100}:\s{0,100}"[^"]{1,2000}({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}"""",
  ]
  DupFields = [ "host->dest_host" ]


}
```
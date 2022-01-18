#### Parser Content
```Java
{
Name = cef-skyformation-login
  Vendor = Cloud Application
  Product = Cloud Application
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """|Skyformation|""", """|login-success|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """\Wend=({time}\d{1,100})""",
    """(created_at|eventTime)"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """\WdestinationServiceName =(|({event_subtype}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({dproc}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdtz=(|({dtz}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString1=(|({activity}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg=(|({additional_info}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """(\||\s)requestClientApplication=(|({app}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WsourceServiceName =(|({service}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsuser=([^\s]{1,2000}\/)?(|({user}[^=@]{1,2000}?)(@({domain}[^.\s]{1,2000})?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssuser=[^=]{0,2000}?@([\.\w+]{1,2000}\.)?({email_domain}[^\.\s]{1,2000}\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{1,100}""",
    """\ssuser=([^\s]{1,2000}\/)?({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=(({user_fullname}\w+(\s{1,100}\w+)+)[^\w=]|({user}[^@\s]{1,2000})\s{1,100}\w+=)""",
    """\Wext_eventType=(|({log_type}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"source"\s{0,100}:\s{0,100}\{[^=]{1,2000}?"{1,20}name"{1,20}:"{1,20}({user_fullname}[^\"]{1,2000})"{1,20}""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({user_agent}[^"]{1,2000}?)"\s{0,100}[,\}\]]""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({browser}[\w\-]{1,2000})\/[\d\._]{1,2000}""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"Mozilla\/[^"]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]


}
```
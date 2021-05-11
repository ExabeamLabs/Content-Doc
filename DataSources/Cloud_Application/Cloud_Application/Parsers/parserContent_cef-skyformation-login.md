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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",   
    """\Wend=({time}\d{1,100})""",
    """(created_at|eventTime)"{1,20}:"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}\w [\w\-.]+ Skyformation""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
    """\WdestinationServiceName=(|({event_subtype}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({dproc}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdtz=(|({dtz}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WflexString1=(|({activity}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg=(|({additional_info}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """(\||\s)requestClientApplication=(|({app}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WsourceServiceName=(|({service}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=([^\s]+\/)?(|({user}[^=@]+?)(@({domain}[^.\s]+)?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssuser=[^=]*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s{1,100}""",
    """\ssuser=([^\s]+\/)?({user_email}[^\s@]+@[^\s@]+)\s{1,100}(\w+=|$)""",
    """\Wsuser=(({user_fullname}\w+(\s{1,100}\w+)+)[^\w=]|({user}[^@\s]+)\s{1,100}\w+=)""",
    """\Wext_eventType=(|({log_type}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"source"\s{0,100}:\s{0,100}\{[^=]+?"{1,20}name"{1,20}:"{1,20}({user_fullname}[^\"]+)"{1,20}""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({user_agent}[^"]+?)"\s{0,100}[,\}\]]""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({browser}[\w\-]+)\/[\d\._]+""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]
}
```
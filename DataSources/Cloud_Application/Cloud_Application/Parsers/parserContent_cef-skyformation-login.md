#### Parser Content
```Java
{
Name = cef-skyformation-login
  Vendor = Cloud Application
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """|Skyformation|""", """|login-success|""" ]
  Fields = [
    """\Wend=({time}\d+)""",
    """exabeam_host=({host}[^\s]+)""",
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+\w ({host}[\w\-.]+) Skyformation""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
    """\WdestinationServiceName=(|({event_subtype}.+?))(\s+\w+=|\s*$)""",
    """\Wdproc=(|({dproc}.+?))(\s+\w+=|\s*$)""",
    """\Wdtz=(|({dtz}.+?))(\s+\w+=|\s*$)""",
    """\WflexString1=(|({activity}.+?))(\s+\w+=|\s*$)""",
    """\Wmsg=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
    """(\||\s)requestClientApplication=(|({app}.+?))(\s+\w+=|\s*$)""",
    """\WsourceServiceName=(|({service}.+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wsuser=([^\s]+\/)?(|({user}[^=@]+?)(@({domain}[^.\s]+)?))(\s+\w+=|\s*$)""",
    """\ssuser=[^=]*?@([\.\w+]+\.)?({email_domain}[^\.\s]+\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch))\s+""",
    """\ssuser=([^\s]+\/)?({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
    """\Wsuser=(({user_fullname}\w+(\s+\w+)+)[^\w=]|({user}[^\s]+)\s+\w+=)""",
    """\Wext_eventType=(|({event_type}.+?))(\s+\w+=|\s*$)""",
    """"source"\s*:\s*\{.+?"+name"+:"+({user_fullname}[^\"]+)"+""",
    """"user(A|a)gent"\s*:\s*"({user_agent}[^"]+?)"\s*[,\}\]]""",
    """"user(A|a)gent"\s*:\s*"({browser}[\w\-]+)\/[\d\._]+""",
    """"user(A|a)gent"\s*:\s*"Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]
}
```
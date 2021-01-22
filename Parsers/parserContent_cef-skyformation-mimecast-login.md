#### Parser Content
```Java
{
Name = cef-skyformation-mimecast-login
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """|login-success|""",  """destinationServiceName=Mimecast Email Security"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventTime":"({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+)""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
    """\WdestinationServiceName=(|({event_subtype}[^=]+?))(\s+\w+=|\s*$)""",
    """\Wdproc=(|({dproc}[^=]+?))(\s+\w+=|\s*$)""",
    """\Wdtz=(|({dtz}[^=]+?))(\s+\w+=|\s*$)""",
    """"auditType":"({activity}[^"]+)""",
    """\Wmsg=(|({additional_info}[^=]+?))(\s+\w+=|\s*$)""",
    """({outcome}(?i)success)""",
    """\WrequestClientApplication=(|({app}[^=]+?))(\s+\w+=|\s*$)""",
    """({app}Mimecast Email Security)""",
    """\WsourceServiceName=(|({service}[^=]+?))(\s+\w+=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """"user":"({user_email}[^"]+)""",
    """"user(A|a)gent"\s*:\s*"({user_agent}[^"]+?)"\s*[,\}\]]""",
    """"user(A|a)gent"\s*:\s*"({browser}[\w\-]+)\/[\d\._]+""",
    """"user(A|a)gent"\s*:\s*"Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]
}
```
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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"eventTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100})""",
    """([^\|]*\|){5}({activity}[^\|]+)""",
    """\WdestinationServiceName=(|({event_subtype}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({dproc}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdtz=(|({dtz}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"auditType":"({activity}[^"]+)""",
    """\Wmsg=(|({additional_info}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """({outcome}(?i)success)""",
    """\WrequestClientApplication=(|({app}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """({app}Mimecast Email Security)""",
    """\WsourceServiceName=(|({service}[^=]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """"user":"({user_email}[^"]+)""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({user_agent}[^"]+?)"\s{0,100}[,\}\]]""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({browser}[\w\-]+)\/[\d\._]+""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]
}
```
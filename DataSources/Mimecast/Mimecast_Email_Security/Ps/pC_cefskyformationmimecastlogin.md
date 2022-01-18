#### Parser Content
```Java
{
Name = cef-skyformation-mimecast-login
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """|Skyformation|""", """|login-success|""",  """destinationServiceName =Mimecast Email Security"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventTime":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100})""",
    """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
    """\WdestinationServiceName =(|({event_subtype}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdproc=(|({dproc}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdtz=(|({dtz}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """"auditType":"({activity}[^"]{1,2000})""",
    """\Wmsg=(|({additional_info}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """({outcome}(?i)success)""",
    """\WrequestClientApplication=(|({app}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """({app}Mimecast Email Security)""",
    """\WsourceServiceName =(|({service}[^=]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"user":"({user_email}[^"]{1,2000})""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({user_agent}[^"]{1,2000}?)"\s{0,100}[,\}\]]""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"({browser}[\w\-]{1,2000})\/[\d\._]{1,2000}""",
    """"user(A|a)gent"\s{0,100}:\s{0,100}"Mozilla\/[^"]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
  ]


}
```
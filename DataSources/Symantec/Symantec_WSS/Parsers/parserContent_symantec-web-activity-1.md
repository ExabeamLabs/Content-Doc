#### Parser Content
```Java
{
Name = symantec-web-activity-1
  Vendor = Symantec
  Product = Symantec WSS
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName=Symantec WSS""", """requestClientApplication=Broadcom WSS API""", """|Skyformation|""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s[^\s]+\sSkyformation""",
    """cs6=.+?\d\d:\d\d:\d\d,\s{0,100}({host}[^,\s]+)""",
    """\s{0,100}({failure_reason}[^,]+),\s{0,100}({action}OBSERVED|PROXIED|DENIED),\s{0,100}(?:-|({category}[^,]+)),\s{0,100}(?:-|({referrer}[^,]+)),\s{0,100}(?:-|({result_code}\d{1,100})),\s{0,100}(?:-|({proxy_action}[^,]+)),\s{0,100}(?:-|unknown|({method}[^,]+)),\s{0,100}(?:-|({mime}[^,]+)),\s{0,100}(?:-|({protocol}[^,]+)),\s{0,100}(?:-|({web_domain}[^,]+)),\s{0,100}(?:-|({dest_port}[^,]+)),\s{0,100}(?:-|({uri_path}[^,\s]+)),.+?,\s[^,]+,\s{0,100}(?:-|({user_agent}[^,]+)),\s{0,100}""",
    """Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """cs6=\[.+({user_agent}Mozilla.+?),\s{0,100}(?:-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\sproto=(-|({protocol}\d{1,100}))""",
    """\ssuid=({uid}[^\s]+)""",
    """\Wsuser=(({domain}[^\\\s]+)\\+)?(non-interactive-user|(-|anonymous|(?i)unauthenticated|({user}[^\\\s]+)))""",
    """\sapp=(-|({category}.+?))\s\w+=""",
    """\sdhost=(-|({web_domain}.+?))\s\w+=""",
    """\sdst=(-|({dest_ip}.+?))\s\w+=""",
    """\sflexString1=(-|({proxy_action}.+?))\s\w+=""",
    """\ssrc=(-|({src_ip}.+?))\s\w+=""",
    """\Wdproc=(|-|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```
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
    """cs6=.+?\d\d:\d\d:\d\d,\s*({host}[^,\s]+)""",
    """\s*({failure_reason}[^,]+),\s*({action}OBSERVED|PROXIED|DENIED),\s*(?:-|({category}[^,]+)),\s*(?:-|({referrer}[^,]+)),\s*(?:-|({result_code}\d+)),\s*(?:-|({proxy_action}[^,]+)),\s*(?:-|unknown|({method}[^,]+)),\s*(?:-|({mime}[^,]+)),\s*(?:-|({protocol}[^,]+)),\s*(?:-|({web_domain}[^,]+)),\s*(?:-|({dest_port}[^,]+)),\s*(?:-|({uri_path}[^,\s]+)),.+?,\s[^,]+,\s*(?:-|({user_agent}[^,]+)),\s*""",
    """Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """cs6=\[.+({user_agent}Mozilla.+?),\s*(?:-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\sproto=(-|({protocol}\d+))""",
    """\ssuid=({uid}[^\s]+)""",
    """\Wsuser=(({domain}[^\\\s]+)\\+)?(non-interactive-user|(-|anonymous|(?i)unauthenticated|({user}[^\\\s]+)))""",
    """\sapp=(-|({category}.+?))\s\w+=""",
    """\sdhost=(-|({web_domain}.+?))\s\w+=""",
    """\sdst=(-|({dest_ip}.+?))\s\w+=""",
    """\sflexString1=(-|({proxy_action}.+?))\s\w+=""",
    """\ssrc=(-|({src_ip}.+?))\s\w+=""",
    """\Wdproc=(|-|({process_name}.+?))(\s+\w+=|\s*$)""",
  ]
}
```
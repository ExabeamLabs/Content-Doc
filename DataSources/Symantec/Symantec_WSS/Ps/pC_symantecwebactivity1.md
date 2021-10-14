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
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s[^\s]{1,2000}\sSkyformation""",
    """cs6=.+?\d\d:\d\d:\d\d,\s{0,100}({host}[^,\s]{1,2000})""",
    """\s{0,100}({failure_reason}[^,]{1,2000}),\s{0,100}({action}OBSERVED|PROXIED|DENIED),\s{0,100}(?:-|({category}[^,]{1,2000})),\s{0,100}(?:-|({referrer}[^,]{1,2000})),\s{0,100}(?:-|({result_code}\d{1,100})),\s{0,100}(?:-|({proxy_action}[^,]{1,2000})),\s{0,100}(?:-|unknown|({method}[^,]{1,2000})),\s{0,100}(?:-|({mime}[^,]{1,2000})),\s{0,100}(?:-|({protocol}[^,]{1,2000})),\s{0,100}(?:-|({web_domain}[^,]{1,2000})),\s{0,100}(?:-|({dest_port}[^,]{1,2000})),\s{0,100}(?:-|({uri_path}[^,\s]{1,2000})),.+?,\s[^,]{1,2000},\s{0,100}(?:-|({user_agent}[^,]{1,2000})),\s{0,100}""",
    """cs6=\[.+({user_agent}Mozilla.+?),\s{0,100}(?:-|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """\sproto=(-|({protocol}\d{1,100}))""",
    """\ssuid=({uid}[^\s]{1,2000})""",
    """\Wsuser=(({domain}[^\\\s]{1,2000})\\+)?(non-interactive-user|(-|anonymous|(?i)unauthenticated|({user}[^\\\s]{1,2000})))""",
    """\sapp=(-|({category}.+?))\s\w+=""",
    """\sdhost=(-|({web_domain}.+?))\s\w+=""",
    """\sdst=(-|({dest_ip}.+?))\s\w+=""",
    """\sflexString1=(-|({proxy_action}.+?))\s\w+=""",
    """\ssrc=(-|({src_ip}.+?))\s\w+=""",
    """\Wdproc=(|-|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```
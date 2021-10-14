#### Parser Content
```Java
{
Name = symantec-web-activity
  Vendor = Symantec
  Product = Symantec WSS
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """requestClientApplication=Symantec WSS"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({action}OBSERVED|PROXIED|DENIED),"{0,20}\s{0,100}({category}.+?)"{0,20},\s(?:-|({referrer}.+?))\s{0,100},\s(?:-|({result_code}(0|[1-5]\d\d))),\s(?:-|unknown|({proxy_action}[^,]{1,2000})),\s""",
    """, ({action}OBSERVED|PROXIED|DENIED),([^,]{1,2000},){1}(\s{0,100}-,\s|(.+?,\s))([^,]{1,2000},){2}\s{0,100}(?:-|unknown|({method}(GET|POST|PUT|TUNNEL|OPTIONS|CONNECT|HEAD|DELETE))),\s{0,100}(?:-|({mime}[^,]{1,2000})),\s(?:-|({protocol}[^,]{1,2000})),\s({full_url}[^\s]{1,2000}?),\s(?:-|({dest_port}\d{1,100})),\s(?:-|({uri_path}[^\s]{1,2000}?))\s{0,100},\s(-|({uri_query}[^\s]{1,2000}?)),([^,]{1,2000},){1}\s({user_agent}[^-]{1,2000}?),\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
    """, ({action}OBSERVED|PROXIED|DENIED),([^,]{1,2000},){1}(\s{0,100}-,\s|(.+?,\s))([^,]{1,2000},){2}\s{0,100}(?:-|unknown|({method}(GET|POST|PUT|TUNNEL|OPTIONS|CONNECT|HEAD|DELETE))),\s{0,100}(?:-|({mime}[^,]{1,2000})),\s(?:-|({protocol}[^,]{1,2000})),\s({full_url}[^\s]{1,2000}?),\s(?:-|({dest_port}\d{1,100})),\s(?:-|({uri_path}[^\s]{1,2000}?))\s{0,100},\s(-|({uri_query}[^\s]{1,2000}?)),"""
    """, ({action}OBSERVED|PROXIED|DENIED),([^,]{1,2000},){4}\s{0,100}(?:-|unknown|({method}(GET|POST|PUT|TUNNEL|OPTIONS|CONNECT|HEAD|DELETE))),\s{0,100}(?:-|({mime}[^,]{1,2000})),\s(?:-|({protocol}[^,]{1,2000})),\s({full_url}[^,]{1,2000}),\s(?:-|({dest_port}\d{1,100})),\s(?:-|({uri_path}[^,]{1,2000}))\s{0,100},\s(-|({uri_query}[^,]{1,2000})),"""
    """,\s{0,100}({user_agent}(iOS|Android|BlackBerry|Microsoft|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident|Mozilla|Breakpad)[^,]{1,2000}),"""
    """cs6=.+?({time}\d\d\d\d-\d\d-\d\d,\s\d\d:\d\d:\d\d),""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}.\d{1,100}Z)""",
    """\sproto=({protocol}\d{1,100})""",
    """\ssuid=(anonymous|({uid}[^\s]{1,2000}))""",
    """\ssuser=(({domain}[^\\\s]{1,2000})\\+)?(anonymous|system-process|({user}[^\s]{1,2000}))""",
    """\Wsuser=(({domain}[^\\\s]{1,2000})\\+)?(non-interactive-user|anonymous|system-process({user}[^\\\s]{1,2000}))""",
    """\sapp=({category}.+?)\s\w+=""",
    """\sdhost=({web_domain}.+?)\s\w+=""",
    """\sdst=({dest_ip}[a-fA-F:\d.]{1,2000})\s{0,100}(\w+=|$)""",
    """\sflexString1=({proxy_action}.+?)\s\w+=""",
    """\ssrc=({src_ip}[a-fA-F:\d.]{1,2000})\s{0,100}(\w+=|$)""",
    """\Wdproc=(|({process_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```
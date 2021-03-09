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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({action}OBSERVED|PROXIED|DENIED),"*\s*({category}.+?)"*,\s(?:-|({referrer}.+?))\s*,\s(?:-|({result_code}(0|[1-5]\d\d))),\s(?:-|unknown|({proxy_action}[^,]+)),\s""",
    """, ({action}OBSERVED|PROXIED|DENIED),([^,]+,){1}(\s*-,\s|(.+?,\s))([^,]+,){2}\s*(?:-|unknown|({method}(GET|POST|PUT|TUNNEL|OPTIONS|CONNECT|HEAD|DELETE))),\s*(?:-|({mime}[^,]+)),\s(?:-|({protocol}[^,]+)),\s({full_url}[^\s]+?),\s(?:-|({dest_port}\d+)),\s(?:-|({uri_path}[^\s]+?))\s*,\s(-|({uri_query}[^\s]+?)),([^,]+,){1}\s({user_agent}[^-]+?),\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"""
    """, ({action}OBSERVED|PROXIED|DENIED),([^,]+,){1}(\s*-,\s|(.+?,\s))([^,]+,){2}\s*(?:-|unknown|({method}(GET|POST|PUT|TUNNEL|OPTIONS|CONNECT|HEAD|DELETE))),\s*(?:-|({mime}[^,]+)),\s(?:-|({protocol}[^,]+)),\s({full_url}[^\s]+?),\s(?:-|({dest_port}\d+)),\s(?:-|({uri_path}[^\s]+?))\s*,\s(-|({uri_query}[^\s]+?)),"""
    """, ({action}OBSERVED|PROXIED|DENIED),([^,]+,){4}\s*(?:-|unknown|({method}(GET|POST|PUT|TUNNEL|OPTIONS|CONNECT|HEAD|DELETE))),\s*(?:-|({mime}[^,]+)),\s(?:-|({protocol}[^,]+)),\s({full_url}[^,]+),\s(?:-|({dest_port}\d+)),\s(?:-|({uri_path}[^,]+))\s*,\s(-|({uri_query}[^,]+)),"""
    """,\s*({user_agent}(iOS|Android|BlackBerry|Microsoft|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin|Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident|Mozilla|Breakpad)[^,]+),"""
    """cs6=.+?({time}\d\d\d\d-\d\d-\d\d,\s\d\d:\d\d:\d\d),""",
    """({time}\d+-\d+-\d+T\d+:\d+:\d+.\d+Z)""",
    """\sproto=({protocol}\d+)""",
    """\ssuid=(anonymous|({uid}[^\s]+))""",
    """\ssuser=(({domain}[^\\\s]+)\\+)?(anonymous|system-process|({user}[^\s]+))""",
    """\Wsuser=(({domain}[^\\\s]+)\\+)?(non-interactive-user|anonymous|system-process({user}[^\\\s]+))""",
    """\sapp=({category}.+?)\s\w+=""",
    """\sdhost=({web_domain}.+?)\s\w+=""",
    """\sdst=({dest_ip}[a-fA-F:\d.]+)\s*(\w+=|$)""",
    """\sflexString1=({proxy_action}.+?)\s\w+=""",
    """\ssrc=({src_ip}[a-fA-F:\d.]+)\s*(\w+=|$)""",
    """\Wdproc=(|({process_name}.+?))(\s+\w+=|\s*$)""",
    """Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```
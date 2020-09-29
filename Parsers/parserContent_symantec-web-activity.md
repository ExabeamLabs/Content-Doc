#### Parser Content
```Java
{
Name = symantec-web-activity
  Vendor = Symantec
  Product = Symantec WSS
  Lms = Syslog
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSZ"
  Conditions = [ """requestClientApplication=Symantec WSS"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({action}OBSERVED|PROXIED|DENIED)\s"*({category}[^"]+)"*\s(?:-|({referrer}[^\s]+))\s({result_code}\d+)\s({proxy_action}[^\s]+)\s({method}[^\s]+)\s(?:-|({mime}[^\s]+))\s({protocol}[^\s]+)\s({dest_host}[^\s]+)\s({dest_port}\d+)\s.*?\s(?:-|({request_uri}[^\s]+)).*?"+({user_agent}[^"]+)""",
    """cs6=\d+\s({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)\s".*?"\s({result_code}\d+)\s""",
    """\sproto=({protocol}\d+)""",
    """\ssuid=({uid}[^\s]+)""",
    """\ssuser=({domain}[^\\]+)\\?({user}[^\s]+)""",
    """\Wsuser=(({domain}[^\\\s]+)\\+)?(non-interactive-user|({user}[^\\\s]+))""",
    """\sapp=({category}.+?)\s\w+=""",
    """\sdhost=({dest_host}.+?)\s\w+=""",
    """\sdst=({dest_ip}.+?)\s\w+=""",
    """\sflexString1=({proxy_action}.+?)\s\w+=""",
    """\ssrc=({src_ip}.+?)\s\w+=""",
    """\Wdproc=(|({process_name}.+?))(\s+\w+=|\s*$)""",
    """Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)"""
  ]
}
```
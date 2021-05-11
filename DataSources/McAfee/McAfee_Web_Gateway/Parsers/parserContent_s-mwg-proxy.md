#### Parser Content
```Java
{
Name = s-mwg-proxy
  Vendor = McAfee
  Product = McAfee Web Gateway
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """mwg: status="""", """srcip="""", """mtd="""", """urlp="""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}mwg:""",
    """\Wstatus="({result_code}\d{1,100})""",
    """\Wsrcip="(|({src_ip}[^"]+))"""",
    """\Wuser="(-|({user}[^"]+))"""",
    """\Wdst_ip="(-|({dest_ip}[^"]+))"""",
    """\Wurlp="(-|({dest_port}\d{1,100}))""",
    """\Wproto="(-|({protocol}[^"]+))"""",
    """\Wmtd="(-|({method}[^"]+))"""",
    """\Wurlc="(-|({category}[^"]+))"""",
    """\Wmt="(-|({mime}[^"]+))"""",
    """\Wbytes="(-|({bytes_in}\d{1,100})\/({bytes_out}\d{1,100})\/({bytes_in_post}\d{1,100})\/({bytes_in_get}\d{1,100}))"""",
    """\Wua="(-|({user_agent}[^"]+))"""",
    """\Wrule="(-|({proxy_action}[^"]+))"""",
    """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wurl="(-|({full_url}[^"]+))"""",
    """\Wurl="(?:[^:]+:\/+)({web_domain}[^\/:\s]+)""",
    """\Wurl="(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s]+)""",
    """\Wurl="(-|([^?]+({uri_query}\?[^\s"]+)))""",
    """\Wurl="(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|:|\/|$))[^\s\/:]+)"""
  ]
}
```
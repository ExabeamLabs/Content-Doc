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
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+mwg:""",
    """\Wstatus="({result_code}\d+)""",
    """\Wsrcip="(|({src_ip}[^"]+))"""",
    """\Wuser="(-|({user}[^"]+))"""",
    """\Wdst_ip="(-|({dest_ip}[^"]+))"""",
    """\Wurlp="(-|({dest_port}\d+))""",
    """\Wproto="(-|({protocol}[^"]+))"""",
    """\Wmtd="(-|({method}[^"]+))"""",
    """\Wurlc="(-|({category}[^"]+))"""",
    """\Wmt="(-|({mime}[^"]+))"""",
    """\Wbytes="(-|({bytes_in}\d+)\/({bytes_out}\d+)\/({bytes_in_post}\d+)\/({bytes_in_get}\d+))"""",
    """\Wua="(-|({user_agent}[^"]+))"""",
    """\Wrule="(-|({proxy_action}[^"]+))"""",
    """Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wurl="(-|({full_url}[^"]+))"""",
    """\Wurl="(?:[^:]+:\/+)({web_domain}[^\/:\s]+)""",
    """\Wurl="(?:-|\w+:\/+[^\/]+)({uri_path}\/[^?\s]+)""",
    """\Wurl="(-|([^?]+({uri_query}\?[^\s"]+)))""",
    """\Wurl="(.*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|:|\/|$))[^\s\/:]+)"""
  ]
}
```
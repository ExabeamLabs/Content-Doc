#### Parser Content
```Java
{
Name = websense-proxy-2
  Vendor = Forcepoint
  Product = Websense Secure Gateway
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """category=""", """bytes_out=""", """bytes_in=""", """http_method="""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+(\w+=|$)""",
    """\Wcategory="?({category}.+?)"?,?\s*(\w+=|$)""",
    """\Wsrc_host="?({src_host}.+?)"?,?\s*(\w+=|$)""",
    """\Wsrc_host="?({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wde?st="?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Whost_masked="?({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdest_ip_masked="?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdst_ip="?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wbytes_out="?({bytes_in}\d+)""",
    """\Wbytes_in="?({bytes_out}\d+)""",
    """\Whttp_method="?({method}.+?)"?,?\s*(\w+=|$)""",
    """\Wstatus="?({result_code}\d+)""",
    """\Whttp_proxy_status_code="?({result_code}\d+)""",
    """\Whttp_server_status_code="?({result_code}\d+)""",
    """\Wdisposition="?({action}.+?)"?,?\s*(\w+=|$)""",
    """\Waction="?(?:-|({action}.+?))"?,?\s*(\w+=|$)""",
    """\Wurl="?({full_url}.+?)"?,?\s+(\w+=|$)""",
    """\Wurl="?(?:-|({protocol}\w+))\\*:\/+""",
    """\Wurl="?(?:-|(\w+\\*:\/+)?[^\/"=]+)({uri_path}\/[^\/][^?\s"]*)""",
    """\Wurl="?[^\?\s"=]*({uri_query}\?[^\s"]*)"?,?(\s+\w+=|\s*$)""",
    """\Wurl="?(?:[^:]+\\*:\/+)?({web_domain}[^\/:\s"]+)""",
    """\Wurl="?(\w+\\*:\/+)?([^\/]*?)({top_domain}(?!(?:\d+\.){3}\d+)[^\.\s\/:"]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|br))+)(\s|\/|$|:|")""",
    """\Wcache="*({proxy_action}.+?)"*,?\s*(\w+=|$)""",
    """\WReferer="*({referrer}.+?)"*,?\s*(\w+=|$)""",
    """\Whttp_content_type="?(?:-|({mime}.+?))"?,?\s*(\w+=|$)""",
    """\Whttp_user_agent="*({user_agent}[^"]+?)(\s"|")""",
    """\Whttp_user_agent="*(?:-|Mozilla\/.+\([^\)]*?({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wuser="?({user}.+?)"?,?\s*(\w+=|$)""",
    """\Wuser="?LDAP.+?DC\\*=org\/({user}.+?)"?,?\s*(\w+=|$)"""
  ]
}
```
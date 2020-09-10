#### Parser Content
```Java
{
Name = cisco-umbrella-proxy
  Vendor = Cisco Umbrella
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName=Cisco Umbrella """, """dproc=Proxy """, """ext_url=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({host}[\w\-.]+)\s+Skyformation """,
    """\W(destinationServiceName|requestClientApplication)=({app}.+?)(\s+\w+=|\s*$)""",
    """\Wsuser=(anonymous|({user}.+?))(\s+\w+=|\s*$)""",
    """\Wext_contentTpe=({mime}[^\s;]+)""",
    """\Wend=({time}\d+)""",
    """\Wext_externalIp=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wext_internalIp=({src_ip}[a-fA-F\d.:]+)""",
    """\Wext_destinationIp=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wext_responseSize=({bytes_out}\d+)""",
    """\Wext_requestSize=({bytes_in}\d+)""",
    """\Wext_statusCode=({result_code}\d+)""",
    """\Wext_timestamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\Wext_verdict=(|({action}.+?))(\s+\w+=|\s*$)""",
    """\Wext_referer=(|({referrer}.+?))(\s+\w+=|\s*$)""",
    """\Wext_userAgent=(|({user_agent}.+?))(\s+\w+=|\s*$)""",
    """\Wext_url=(-|({full_url}(({protocol}[^:\\\/\s,"]+):[\\\/]+)?(({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({web_domain}[^\\\/\s:,"]+))?(:({dest_port}\d+))?({uri_path}\/[^\s\?"]*)?({uri_query}\?[^"\s]*)?))(\s+\w+=|\s*$)""",
    """\Wext_url=\S*?({top_domain}[^\.\s:\/]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|ch|local|tr))+)(\s|\/)""",
    """\Wext_userAgent=[^=]*?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^=]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\Wext_url=({protocol}http(s)?)""",
  ]
}
```
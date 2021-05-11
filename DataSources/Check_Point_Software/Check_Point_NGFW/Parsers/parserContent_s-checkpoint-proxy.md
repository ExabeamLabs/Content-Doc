#### Parser Content
```Java
{
Name = s-checkpoint-proxy
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Splunk
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ Action="""", """product="URL Filtering"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\-+\d{1,100}:\d\d\s{1,100}({host}\S+)\s{1,100}""",
    """\WAction="({action}[^"]+)""",
    """\Wsrc="({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst="({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wappi_name="(\*+|({web_domain}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^"\/]+))"""",
    """\Wmatched_category="(\*+|({category}[^"]+))"""",
    """\Wweb_client_type="({user_agent}[^"]+)""",
    """\Wweb_client_type="(Other: )?(?:-|({browser}[^\/;]+).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """\Wweb_client_type="(Other: )?(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wresource="({full_url}[^"]+)""",
    """\Wresource="({protocol}[^:"]+)""",
    """\Wresource="(?:[^:]+:\/+)({web_domain}[^\/:\s]+)""",
    """\Wresource="(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]+(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|$))[^\s\/]+)""",
    """\Wresource="(\w+:\/+[^\/]+({uri_path}\/[^?"]+))""",
    """\Wresource="(\w+:\/+[^?]+(|({uri_query}[^"]+)))"""",
    """\Wuser=".+?\(({user}[^)]+)\)""",
    """\Wsrc_user_name=".+?\(({user}[^)]+)\)""",
    """\Wsrc_machine_name="({src_host}[^@"]+)(@({domain}[^@"]+))?""",
    """\Wservice="({dest_port}\d{1,100})""",
    """\Ws_port="({src_port}\d{1,100})""",
    """\Wsent_bytes="({bytes_out}\d{1,100})""",
    """\Wreceived_bytes="({bytes_in}\d{1,100})""",
  ]
}
```
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
    """\WAction="({action}[^"]{1,2000})""",
    """\Wsrc="({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst="({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wappi_name="(\*+|({web_domain}(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^"\/]{1,2000}))"""",
    """\Wmatched_category="(\*+|({category}[^"]{1,2000}))"""",
    """\Wweb_client_type="({user_agent}[^"]{1,2000})""",
    """\Wweb_client_type="(Other: )?(?:-|({browser}[^\/;]{1,2000}).+({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin))""",
    """\Wweb_client_type="(Other: )?(?:-|Mozilla\/.+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin).+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
    """\Wresource="({full_url}[^"]{1,2000})""",
    """\Wresource="({protocol}[^:"]{1,2000})""",
    """\Wresource="(?:[^:]{1,2000}:\/+)({web_domain}[^\/:\s]{1,2000})""",
    """\Wresource="(.*?)({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|\/|$))[^\s\/]{1,2000})""",
    """\Wresource="(\w+:\/+[^\/]{1,2000}({uri_path}\/[^?"]{1,2000}))""",
    """\Wresource="(\w+:\/+[^?]{1,2000}(|({uri_query}[^"]{1,2000})))"""",
    """\Wuser=".+?\(({user}[^)]{1,2000})\)""",
    """\Wsrc_user_name=".+?\(({user}[^)]{1,2000})\)""",
    """\Wsrc_machine_name="({src_host}[^@"]{1,2000})(@({domain}[^@"]{1,2000}))?""",
    """\Wservice="({dest_port}\d{1,100})""",
    """\Ws_port="({src_port}\d{1,100})""",
    """\Wsent_bytes="({bytes_out}\d{1,100})""",
    """\Wreceived_bytes="({bytes_in}\d{1,100})""",
  ]
}
```
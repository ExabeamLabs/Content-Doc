#### Parser Content
```Java
{
Name = s-mwg-proxy-1
  Vendor = McAfee
  Product = McAfee Web Gateway
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """mwg: """, """status="""", """srcip="""", """mtd="""", """urlp="""", """ua="""", """cache="""" ]
  Fields = [
    """mwg:\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}?@\s{0,100})?({host}[\w.-]{1,2000})""",
    """dhost="(-|({dest_host}[^"]{1,2000}))""",
    """status="({result_code}\d{1,100})""",
    """srcip="({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """user="(-|({user}[^"]{1,2000}))"""",
    """dstip="(-|({dest_ip}[a-fA-F\d:.]{1,2000}))"""",
    """srcp="(-|({src_port}\d{1,100}))"""",
    """urlp="(-|({dest_port}\d{1,100}))""",
    """proto="(-|({protocol}[^"]{1,2000}))"""",
    """\smtd="(-|({method}[^"]{1,2000}))"""",
    """urlc="(-|({categories}[^"]{1,2000}))"""",
    """urlc="(-|({category}[^",]{1,2000}))""",
    """\smt="(-|({mime}[^"]{1,2000}))"""",
    """app="(-|({app}[^"]{1,2000}))"""",
    """bytes="(-|({bytes_in}\d{1,100})\/({bytes_out}\d{1,100})\/({bytes_in_post}\d{1,100})\/({bytes_in_get}\d{1,100}))"""",
    """\sua="(_|({user_agent}[^"]{1,2000}))"""",
    """\sua="({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """rule="(-|({proxy_action}[^"]{1,2000}))"""",
    """Mozilla\/[^"]{1,2000}?\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """\surl="(-|({full_url}[^"]{1,2000}))"""",
    """\surl="(?:[^:]{1,2000}:\/+)((\d{1,3}\.){3}\d{1,3}|({web_domain}[^\/:\s"]{1,2000}))""",
    """\surl="(-|\w+:\/+[^\/]{1,2000})({uri_path}\/[^?\s"]{1,2000})({uri_query}\?[^\s"]{1,2000})?""", 
    """\surl="[^"]{0,2000}?({top_domain}(?!(?:\d{1,100}\.){3}\d{1,100})[^\.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+(\s|:|\/|$))[^\s\/:]{1,2000})""",
    """usrName ="(-|({user}[^"]{1,2000}))""""
  ]


}
```
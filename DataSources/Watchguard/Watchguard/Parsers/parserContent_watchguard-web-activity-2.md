#### Parser Content
```Java
{
Name = watchguard-web-activity-2
  Vendor = Watchguard
  Product = Watchguard
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ProxyAllow""", """msg_id=""", """proxy_act""", """msg=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """(({host}[\w.\-]+)\s{1,100})?\(({time}\d\d\d\d-\d\d-\d\dT\d\d:\s{0,100}\d\d:\s{0,100}\d\d)\)\s{1,100}http[s]?-proxy""",
    """\s{1,100}({protocol}\S+)\s{1,100}({src_ip}[a-fA-F\d.:]+)\s{1,100}({dest_ip}[a-fA-F\d.:]+)\s{1,100}({src_port}\d{1,100})\s{1,100}({dest_port}\d{1,100})\s{1,100}msg="""",
    """\sproxy_act="({proxy_action}[^"]+)"""",
    """\sop="({method}[^"]+)"""",
    """\sarg="(?:\/|({uri_path}[^"]+))"""",
    """\sdstname="({full_url}({web_domain}(?!\*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^"]*?({top_domain}[^\s."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)))"""",
    """\ssent_bytes="({bytes_in}\d{1,100})""",
    """\srcvd_bytes="({bytes_out}\d{1,100})""",
    """\scats="({category}[^"]+)"""",
    """\ssrc_user="({user_email}({user}[^@]+)[^"]+)"""",   
    """action="{1,20}({proxy_action}[^"]+)"""",
  ]
  
}
```
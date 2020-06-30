#### Parser Content
```Java
{
Name = watchguard-web-activity-2
  Vendor = Watchguard
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """ProxyAllow""", """msg_id=""", """proxy_act""", """msg=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """(({host}[\w.\-]+)\s+)?\(({time}\d\d\d\d-\d\d-\d\dT\d\d:\s*\d\d:\s*\d\d)\)\s+http[s]?-proxy""",
    """\s+({protocol}\S+)\s+({src_ip}[a-fA-F\d.:]+)\s+({dest_ip}[a-fA-F\d.:]+)\s+({src_port}\d+)\s+({dest_port}\d+)\s+msg="""",
    """\sproxy_act="({proxy_action}[^"]+)"""",
    """\sop="({method}[^"]+)"""",
    """\sarg="(?:\/|({uri_path}[^"]+))"""",
    """\sdstname="({full_url}({web_domain}(?!\*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^"]*?({top_domain}[^\s."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)))"""",
    """\ssent_bytes="({bytes_in}\d+)""",
    """\srcvd_bytes="({bytes_out}\d+)""",
    """\scats="({category}[^"]+)"""",
    """\ssrc_user="({user_email}({user}[^@]+)[^"]+)"""",   
    """action="+({proxy_action}[^"]+)"""",
  ]
  
}
```
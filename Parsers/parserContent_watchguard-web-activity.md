#### Parser Content
```Java
{
Name = watchguard-web-activity
  Vendor = Watchguard
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """msg="HTTP request"""", """http-proxy""", """dstname="""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """(({host}[\w.\-]+)\s+)?\(({time}\d\d\d\d-\d\d-\d\dT\d\d:\s*\d\d:\s*\d\d)\)\s+http-proxy""",
    """\s+({protocol}\S+)\s+({src_ip}[a-fA-F\d.:]+)\s+({dest_ip}[a-fA-F\d.:]+)\s+({src_port}\d+)\s+({dest_port}\d+)\s+msg="HTTP request"""",
    """\sproxy_act="({proxy_action}[^"]+)"""",
    """\sop="({method}[^"]+)"""",
    """\sdstname="({web_domain}[^"]+)"""",
    """\sarg="({uri_path}[^"\?]+(\?({uri_query}[^"]+))?)"""",
    """\ssent_bytes="({bytes_in}\d+)""",
    """\srcvd_bytes="({bytes_out}\d+)""",
    """\sapp_cat_name="({category}[^"]+)"""",
    """\ssrc_user="({user_email}[^"]+)"""",
    """\sdstname="(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^"]*?({top_domain}[^\s."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""""
  ]
  DupFields = [ "user_email->user" ]
}
```
#### Parser Content
```Java
{
Name = watchguard-web-activity
  Vendor = Watchguard
  Product = Watchguard
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """msg="HTTP request"""", """http-proxy""", """dstname="""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """(({host}[\w.\-]+)\s{1,100})?\(({time}\d\d\d\d-\d\d-\d\dT\d\d:\s{0,100}\d\d:\s{0,100}\d\d)\)\s{1,100}http-proxy""",
    """\s{1,100}({protocol}\S+)\s{1,100}({src_ip}[a-fA-F\d.:]+)\s{1,100}({dest_ip}[a-fA-F\d.:]+)\s{1,100}({src_port}\d{1,100})\s{1,100}({dest_port}\d{1,100})\s{1,100}msg="HTTP request"""",
    """\sproxy_act="({proxy_action}[^"]+)"""",
    """\sop="({method}[^"]+)"""",
    """\sdstname="({web_domain}[^"]+)"""",
    """\sarg="({uri_path}[^"\?]+(\?({uri_query}[^"]+))?)"""",
    """\ssent_bytes="({bytes_in}\d{1,100})""",
    """\srcvd_bytes="({bytes_out}\d{1,100})""",
    """\sapp_cat_name="({category}[^"]+)"""",
    """\ssrc_user="({user_email}[^"]+)"""",
    """\sdstname="(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^"]*?({top_domain}[^\s."]+(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""""
  ]
  DupFields = [ "user_email->user" ]
}
```
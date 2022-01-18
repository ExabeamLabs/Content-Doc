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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(({host}[\w.\-]{1,2000})\s{1,100})?\(({time}\d\d\d\d-\d\d-\d\dT\d\d:\s{0,100}\d\d:\s{0,100}\d\d)\)\s{1,100}http-proxy""",
    """\s{1,100}({protocol}\S+)\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}({dest_ip}[a-fA-F\d.:]{1,2000})\s{1,100}({src_port}\d{1,100})\s{1,100}({dest_port}\d{1,100})\s{1,100}msg="HTTP request"""",
    """\sproxy_act="({proxy_action}[^"]{1,2000})"""",
    """\sop="({method}[^"]{1,2000})"""",
    """\sdstname="({web_domain}[^"]{1,2000})"""",
    """\sarg="({uri_path}[^"\?]{1,2000}(\?({uri_query}[^"]{1,2000}))?)"""",
    """\ssent_bytes="({bytes_in}\d{1,100})""",
    """\srcvd_bytes="({bytes_out}\d{1,100})""",
    """\sapp_cat_name="({category}[^"]{1,2000})"""",
    """\ssrc_user="({user_email}[^"]{1,2000})"""",
    """\sdstname="(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^"]{0,2000}?({top_domain}[^\s."]{1,2000}(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""""
  ]
  DupFields = [ "user_email->user" ]


}
```
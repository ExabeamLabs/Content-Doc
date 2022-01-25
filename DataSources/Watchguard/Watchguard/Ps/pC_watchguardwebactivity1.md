#### Parser Content
```Java
{
Name = watchguard-web-activity-1
  Vendor = Watchguard
  Product = Watchguard
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """msg="HTTPS Request"""", """https-proxy""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(({host}[\w.\-]{1,2000})\s{1,100})?\(({time}\d\d\d\d-\d\d-\d\dT\d\d:\s{0,100}\d\d:\s{0,100}\d\d)\)\s{1,100}https-proxy""",
    """\s{1,100}({protocol}\S+)\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}({dest_ip}[a-fA-F\d.:]{1,2000})\s{1,100}({src_port}\d{1,100})\s{1,100}({dest_port}\d{1,100})\s{1,100}msg="HTTPS Request"""",
    """\sproxy_act="({proxy_action}[^"]{1,2000})"""",
    """\s(cn|sni)="({web_domain}(?!\*|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^"]{0,2000}?([^\s."]{1,2000}))"""",
    """\ssent_bytes="({bytes_in}\d{1,100})""",
    """\srcvd_bytes="({bytes_out}\d{1,100})""",
    """\sapp_cat_name="({category}[^"]{1,2000})"""",
    """\ssrc_user="({user_email}[^"]{1,2000})"""",
    """action="{1,20}({proxy_action}[^"]{1,2000})""""
  ]
  DupFields = [ "user_email->user" ]


}
```
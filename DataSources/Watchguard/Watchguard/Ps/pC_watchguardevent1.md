#### Parser Content
```Java
{
Name = watchguard-event-1
  DataType = "network-connection"
  Conditions = [ """msg_id=""", """3000-0148""", """firewall:""" ]
}
watch-guard-events = {
  Vendor = Watchguard
  Product = Watchguard
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """\ssrc_user="({user_email}({user}[^@]{1,2000})[^"]{1,2000})""",
    """(({host}[\w.\-]{1,2000})\s{1,100})?\(({time}\d\d\d\d-\d\d-\d\dT\d\d:\s{0,100}\d\d:\s{0,100}\d\d)\)\s{1,100}""",
    """\ssent_bytes="({bytes_out}\d{1,100})""",
    """\srcvd_bytes="({bytes_in}\d{1,100})""",
    """\sapp_name="{0,20}({activity}[^"]{1,2000})""",
    """\scat_name="{0,20}({category}[^"]{1,2000})""",
    """\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\s{1,100}({dest_ip}[a-fA-F\d.:]{1,2000})\s{1,100}({src_port}\d{1,100})\s{1,100}({dest_port}\d{1,100})\s{1,100}""",
    """msg_id="{0,20}({event_code}[^"]{1,2000})"{1,20}\s{1,100}(fqdn_dst_match="{1,20}({web_domain}[^"]{1,2000})"{1,20})?\s{0,100}({action}[^\s]{1,2000})(\s{1,100}\S+){2}\s{0,100}\d{0,100}\s{1,100}({protocol}[^\s]{1,2000})""",
    ]}
```
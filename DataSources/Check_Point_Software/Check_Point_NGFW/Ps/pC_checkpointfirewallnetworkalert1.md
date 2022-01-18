#### Parser Content
```Java
{
Name = checkpoint-firewall-network-alert-1
  DataType = "network-alert"
  Conditions = [ """product="VPN-1 & FireWall-1"""", """Action="monitor"""" ]

checkpoint-firewall-4 = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
    """<\d{1,100}>\w+ \d\d \d\d:\d\d:\d\d\S*?\s{1,100}({host}[\w.\-]{1,2000})""",
    """\WAction="({action}[^"]{1,2000})""",
    """\Wrule="({rule}[^"]{1,2000})""",
    """\Wrule_uid="({rule_uid}[^"]{1,2000})""",
    """\Wservice_id="({app_protocol}[^"]{1,2000})""",
    """\Wsrc="({src_ip}[^"]{1,2000})""",
    """\Wdst="({dest_ip}[^"]{1,2000})""",
    """\Wproto="({protocol}[^"]{1,2000})""",
    """\Wpeer gateway="({src_translated_ip}[^"]{1,2000})""",
    """\Wservice="({dest_port}[^"]{1,2000})""",
    """\Ws_port="({src_port}[^"]{1,2000})""",
    """\Wsrc_machine_name="({src_host}[^"]{1,2000})""",
    """\Wsrc_machine_name="({src_host}[^"@]{1,2000})@({domain}[^"]{1,2000})""",
    """\Wdst_machine_name="({dest_host}[^"]{1,2000})""",
    """\Wdst_machine_name="({dest_host}[^"@]{1,2000})@({domain}[^"]{1,2000})""",
    """\W(user|dst_user_name)="({user}[^"]{1,2000})""",
    """\W(user|dst_user_name)="({user_fullname}[^"\(]{1,2000}?)\s{0,100}\(({user}[^\)]{1,2000})""",
  ]
  DupFields = [ "action->event_name" 
}
```
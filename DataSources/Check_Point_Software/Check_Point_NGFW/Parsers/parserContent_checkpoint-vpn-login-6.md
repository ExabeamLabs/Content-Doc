#### Parser Content
```Java
{
Name = checkpoint-vpn-login-6
  DataType = "vpn-login"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Log In"""", """vpn_""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-auth.Fields}[
    """action:"{1,20}({activity}[^"]{1,2000})"""
  ]
  DupFields = [ "activity->event_name" ]
}
checkpoint-auth = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "epoch_sec"
  Fields = [
    """\Wtime:"({time}\d{1,100})""",
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """\Wuser:"({user_lastname}[^,]{1,2000}),\s{0,100}({user_firstname}[\w\s]{1,2000}\S)\s{0,100}\(({user}.+?)\)""",
    """\Wuser:"({user_fullname}[^,:\("]{1,2000})\s\(({user}[^\)]{1,2000})\)""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wendpoint_ip:"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """host_ip:"({dest_ip}[^"]{1,2000})""",
    """\Wauth_method:"({auth_method}[^"]{1,2000})""",
    """\Wauth_status:"({outcome}[^"]{1,2000})""",
    """\sstatus:"({outcome}[^"]{1,2000})""",
    """\Wdomain_name:"({domain}[^"]{1,2000})""",
    """\Worigin:"({origin_ip}[^"]{1,2000})""",
    """\Worigin_sic_name:"CN=({origin_name}[^",]{1,2000})""",
    """\Wproduct:"({product_name}[^"]{1,2000})""",
    """reason:"({failure_reason}[^"]{1,2000})""",
    """\Wsrc_machine_name:"({src_host}[\w\-.]{1,2000})""",
    """\Wifdir:"({direction}[^"]{1,2000})""",
  ]

```
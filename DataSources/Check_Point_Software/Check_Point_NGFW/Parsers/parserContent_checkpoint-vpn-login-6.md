#### Parser Content
```Java
{
Name = checkpoint-vpn-login-6
  DataType = "vpn-login"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Log In"""", """vpn_""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-auth.Fields}[
    """action:"+({activity}[^"]+)"""
  ]
  DupFields = [ "activity->event_name" ]
}
checkpoint-auth = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "epoch_sec"
  Fields = [
    """\Wtime:"({time}\d+)""",
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wuser:"({user_lastname}[^,]+),\s*({user_firstname}[\w\s]+\S)\s*\(({user}.+?)\)""",
    """\Wuser:"({user_fullname}[^,:\("]+)\s\(({user}[^\)]+)\)""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]+)""",
    """\Wendpoint_ip:"({dest_ip}[A-Fa-f:\d.]+)""",
    """host_ip:"({dest_ip}[^"]+)""",
    """\Wauth_method:"({auth_method}[^"]+)""",
    """\Wauth_status:"({outcome}[^"]+)""",
    """\sstatus:"({outcome}[^"]+)""",
    """\Wdomain_name:"({domain}[^"]+)""",
    """\Worigin:"({origin_ip}[^"]+)""",
    """\Worigin_sic_name:"CN=({origin_name}[^",]+)""",
    """\Wproduct:"({product_name}[^"]+)""",
    """reason:"({failure_reason}[^"]+)""",
    """\Wsrc_machine_name:"({src_host}[\w\-.]+)""",
    """\Wifdir:"({direction}[^"]+)""",
  ]

```
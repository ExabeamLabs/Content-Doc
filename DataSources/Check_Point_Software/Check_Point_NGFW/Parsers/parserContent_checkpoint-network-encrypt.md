#### Parser Content
```Java
{
Name = checkpoint-network-encrypt
  DataType = "network-alert"
  Conditions = [ """CheckPoint""", """product:"""", """action:"accept encrypt"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-auth.Fields}[
    """event_name:"+({alert_name}[^"]+)""",
    """cu_rule_category:"+({alert_type}[^"]+)""",
    """proto:"+({protocol}[^"]+)""",
    """cu_rule_id:"+({rule_id}[^"]+)""",
    """service:"+({service}\d+)"""
    """cu_action:"+({action}[^"]+)""",
    """cu_detected_by:"+({src_ip}[^"]+)""",
    """ src:"+({src_ip}[A-Fa-f:\d.]+)""",
    """dst:"+({dest_ip}[^"]+)""",
   
   ]
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
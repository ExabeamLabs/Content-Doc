#### Parser Content
```Java
{
Name = checkpoint-network-encrypt
  DataType = "network-alert"
  Conditions = [ """CheckPoint""", """product:"""", """action:"accept encrypt"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-auth.Fields}[
    """event_name:"{1,20}({alert_name}[^"]+)""",
    """cu_rule_category:"{1,20}({alert_type}[^"]+)""",
    """proto:"{1,20}({protocol}[^"]+)""",
    """cu_rule_id:"{1,20}({rule_id}[^"]+)""",
    """service:"{1,20}({service}\d{1,100})"""
    """cu_action:"{1,20}({action}[^"]+)""",
    """cu_detected_by:"{1,20}({src_ip}[^"]+)""",
    """ src:"{1,20}({src_ip}[A-Fa-f:\d.]+)""",
    """dst:"{1,20}({dest_ip}[^"]+)""",
   
   ]
}
checkpoint-auth = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "epoch_sec"
  Fields = [
    """\Wtime:"({time}\d{1,100})""",
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wuser:"({user_lastname}[^,]+),\s{0,100}({user_firstname}[\w\s]+\S)\s{0,100}\(({user}.+?)\)""",
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
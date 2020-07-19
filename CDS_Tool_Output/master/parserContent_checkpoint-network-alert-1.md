#### Parser Content
```Java
{
Name = checkpoint-network-alert-1
  Vendor = Check Point
  Product = Check Point Threat Prevention
  Lms = Direct
  TimeFormat = "epoch_sec"
  DataType = "network-alert"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Prevent"""" ]
  Fields = [
    """\Wtime:"({time}\d+)""",
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst:"({dest_ip}[A-Fa-f:\d.]+)""",
    """\Waction:"({action}[^"]+)""",
    """\Wmalware_action:"({malware_action}[^"]+)""",
    """\Wmalware_family:"({malware_family}[^"]+)""",
    """\Ws_port:"({src_port}\d+)""",
    """\Wservice:"({dest_port}\d+)""",
    """\Wproto:"({protocol}[^"]+)""",
    """\Wconfidence_level:"({confidence_level}[A-Fa-f:\d.]+)""",
    """\Wifdir:"({direction}[^"]+)""",
    """\Wprotection_name:"({protection_name}[^"]+)""",
    """\Wprotection_type:"({protection_type}[^"]+)""",
    """\Wdestination_dns_hostname:"({destination_dns_hostname}[^"]+)""",
    """\Worigin:"({origin_ip}[^"]+)""",
    """\Worigin_sic_name:"CN=({origin_name}[^",]+)""",
    """\Wproduct:"({product_name}[^"]+)""",
    """\Wrule_uid:"\{({rule_id}[^"\}]+)""",
    """\Wseverity:"({alert_severity}[^"]+)""",

  ]
  DupFields = [ "protection_name->alert_name", "protection_type->alert_type" ]
}
```
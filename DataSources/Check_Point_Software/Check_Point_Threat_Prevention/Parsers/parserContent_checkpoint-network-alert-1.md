#### Parser Content
```Java
{
Name = checkpoint-network-alert-1
  Vendor = Check Point Software
  Product = Check Point Threat Prevention
  Lms = Direct
  TimeFormat = "epoch_sec"
  DataType = "network-alert"
  Conditions = [ """CheckPoint""", """product:"""", """action:"Prevent"""" ]
  Fields = [
    """\Wtime:"({time}\d{1,100})""",
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst:"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Waction:"({action}[^"]{1,2000})""",
    """\Wmalware_action:"({malware_action}[^"]{1,2000})""",
    """\Wmalware_family:"({malware_family}[^"]{1,2000})""",
    """\Ws_port:"({src_port}\d{1,100})""",
    """\Wservice:"({dest_port}\d{1,100})""",
    """\Wproto:"({protocol}[^"]{1,2000})""",
    """\Wconfidence_level:"({confidence_level}[A-Fa-f:\d.]{1,2000})""",
    """\Wifdir:"({direction}[^"]{1,2000})""",
    """\Wprotection_name:"({protection_name}[^"]{1,2000})""",
    """\Wprotection_type:"({protection_type}[^"]{1,2000})""",
    """\Wdestination_dns_hostname:"({destination_dns_hostname}[^"]{1,2000})""",
    """\Worigin:"({origin_ip}[^"]{1,2000})""",
    """\Worigin_sic_name:"CN=({origin_name}[^",]{1,2000})""",
    """\Wproduct:"({product_name}[^"]{1,2000})""",
    """\Wrule_uid:"\{({rule_id}[^"\}]{1,2000})""",
    """\Wseverity:"({alert_severity}[^"]{1,2000})""",

  ]
  DupFields = [ "protection_name->alert_name", "protection_type->alert_type" ]
}
```
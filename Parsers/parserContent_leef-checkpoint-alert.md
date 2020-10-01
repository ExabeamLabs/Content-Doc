#### Parser Content
```Java
{
Name = leef-checkpoint-alert
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """LEEF""", """|Check Point|SmartDefense|""", """attack=""" ]
  Fields = [
    """exabeam_host=[^@]+@\s*({host}[\w\-.]+)""",
    """\Worigin=({host}.+?)(\s+\w+:?=|\s*$)""",
    """\Worigin_sic_name=CN\\=({origin_sic_name}[^,\s]+),""",
    """\Wcat=({alert_type}.+?)(\s+\w+:?=|\s*$)""",
    """\WdevTime=({time}\d+)""",
    """\WperformanceImpact=({performance_impact}\d+)""",
    """\Wsev=({alert_severity}\d+)""",
    """\Wattack=({alert_name}.+?)(\s+\w+:?=|\s*$)""",
    """\Wattack_info=({attack_info}.+?)(\s+\w+:?=|\s*$)""",
    """\Wreason=({additional_info}.+?)(\s+\w+:?=|\s*$)""",
    """\Wconfidence_level=({confidence_level}\d+)""",
    """\WsrcPort=({src_port}\d+)""",
    """\Wservice=({dest_port}\d+)""",
    """\Wprotection_id=({protection_id}.+?)(\s+\w+:?=|\s*$)""",
    """\Wprotection_type=({protection_type}.+?)(\s+\w+:?=|\s*$)""",
    """\Wifdir=({direction}.+?)(\s+\w+:?=|\s*$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\Wproto=({protocol}.+?)(\s+\w+:?=|\s*$)""",
    """\Wrule=({rule_num}.+?)(\s+\w+:?=|\s*$)""",
    """\Wrule_name=({rule}.+?)(\s+\w+:?=|\s*$)""",
    """\Wrule_uid=\{({rule_id}.+?)\}""",
    """\Wloguid=\{({log_uid}.+?)\}""",
    """\Wsrc_machine_name=({src_host}[^@=]+?)(@({domain}.+?))?(\s+\w+:?=|\s*$)""",
    """\Wdst_machine_name=({dest_host}[^@=]+?)(@({domain}.+?))?(\s+\w+:?=|\s*$)""",
    """\Wdst_user_name=({user_fullname}.+?)\s*\(({user}.+?)\)""",
    """\Wsrc_user_name=({user_fullname}.+?)\s*\(({user}.+?)\)""",
    """\WusrName=({user_fullname}.+?)\s*\(({user}.+?)\)""",
    """LEEF:([^\|]*\|){2}({product_name}[^\|]+)""",
    """\Wsignature=({event_name}.+?)(\s+\w+:?=|\s*$)""",
    """\Wsmartdefense_profile=({smartdefense_profile}.+?)(\s+\w+:?=|\s*$)""",
    """\Wurl=({ips_url}.+?)(\s+\w+:?=|\s*$)""",
    """\Wresource_probing=({ips_desc}.+?)(\s+\w+:?=|\s*$)""",
  ]
  DupFields = [ "event_name->protection_name" ]
}
```
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
    """exabeam_host=[^@]{1,2000}@\s{0,100}({host}[\w\-.]{1,2000})""",
    """\Worigin=({host}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Worigin_sic_name=CN\\=({origin_sic_name}[^,\s]{1,2000}),""",
    """\Wcat=({alert_type}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\WdevTime=({time}\d{1,100})""",
    """\WperformanceImpact=({performance_impact}\d{1,100})""",
    """\Wsev=({alert_severity}\d{1,100})""",
    """\Wattack=({alert_name}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wattack_info=({attack_info}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wreason=({additional_info}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wconfidence_level=({confidence_level}\d{1,100})""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\Wservice=({dest_port}\d{1,100})""",
    """\Wprotection_id=({protection_id}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wprotection_type=({protection_type}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wifdir=({direction}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wproto=({protocol}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wrule=({rule_num}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wrule_name=({rule}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wrule_uid=\{({rule_id}.+?)\}""",
    """\Wloguid=\{({log_uid}.+?)\}""",
    """\Wsrc_machine_name=({src_host}[^@=]{1,2000}?)(@({domain}.+?))?(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wdst_machine_name=({dest_host}[^@=]{1,2000}?)(@({domain}.+?))?(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wdst_user_name=({user_fullname}.+?)\s{0,100}\(({user}.+?)\)""",
    """\Wsrc_user_name=({user_fullname}.+?)\s{0,100}\(({user}.+?)\)""",
    """\WusrName =({user_fullname}.+?)\s{0,100}\(({user}.+?)\)""",
    """LEEF:([^\|]{0,2000}\|){2}({product_name}[^\|]{1,2000})""",
    """\Wsignature=({event_name}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wsmartdefense_profile=({smartdefense_profile}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wurl=({ips_url}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wresource_probing=({ips_desc}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
  ]
  DupFields = [ "event_name->protection_name" ]


}
```
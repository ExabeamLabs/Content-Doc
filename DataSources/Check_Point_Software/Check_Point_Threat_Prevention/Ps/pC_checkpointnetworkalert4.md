#### Parser Content
```Java
{
Name = checkpoint-network-alert-4
  Conditions = [ """product:""", """SmartDefense""", """CheckPoint""", """sequencenum""", """attack:""" ]

checkpoint-network-alert = {
  Vendor = Check Point Software
  Product = Check Point Threat Prevention
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wtime:"({time}\d{1,100})""",
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """\Wuser:"({user_lastname}[^,]{1,2000}),\s{0,100}({user_firstname}[\w\s]{1,2000}\S)\s{0,100}\(({account}.+?)\)""",
    """\Wuser:"({user_firstname}[^\s,]{1,2000})\s{1,100}({user_lastname}[^,\(]{1,2000}?)\s{1,100}\(({account}[^\(]{1,2000}?)\)""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst:"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Waction:"({action}[^"]{1,2000})""",
    """\Ws_port:"({src_port}\d{1,100})""",
    """\Wproto:"({protocol}[^"]{1,2000})""",
    """\Wservice:"({dest_port}\d{1,100})""",
    """\Wseverity:"({alert_severity}[^"]{1,2000})""",
    """\Wmessage_info:"({alert_name}[^"]{1,2000})""",
    """\Wmessage_info:"({alert_type}[^"]{1,2000})""",
    """\Wprotection_name:"({protection_name}[^"]{1,2000})""",
    """\Wprotection_name:"({alert_name}[^"]{1,2000})""",
    """\Wprotection_type:"({alert_type}[^"]{1,2000})""",
    """\Wattack_info:"({attack_info}[^"]{1,2000})""",
    """\Wsrc_machine_name:"({src_host}[^"@]{1,2000})@({domain}[^"]{1,2000})""",
    """\Worigin:"({origin_ip}[^"]{1,2000})""",
    """\Worigin_?sic_?name:"CN=({origin_name}[^",]{1,2000})""",
    """\Wproduct:"({product_name}[^"]{1,2000})""",
    """\Wattack:"({attack}[^"]{1,2000})""",
    """\Wconfidence_level:"({confidence_level}[^"]{1,2000})""",
    """\Wrule_name:"({rule_name}[^"]{1,2000})""",
    """\Wrule_uid:"\{({rule_id}[^"\}]{1,2000})""",
    """\Wsmartdefense_profile:"({smartdefense_profile}[^"]{1,2000})""",
    """\Wuser:"({user}[^"\(\)]{1,2000}?)\s{0,100}"""",
    """ifdir:"{1,20}({direction}[^"]{1,2000})""",
    """originsicname:"{1,20}({user_ou}[^"]{1,2000})"""
  
}
```
#### Parser Content
```Java
{
Name = checkpoint-network-alert-3
  DataType = "alert"
  Conditions = [ """CheckPoint""", """product:"Anti Malware"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-firewall-1.Fields}[
    """malware_action:"({alert_type}[^"]+)""",
    """protection_name:"({alert_name}[^"]+)""",
    """severity:"({alert_severity}[^"]+)""""
  ]
}
checkpoint-firewall-1 = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """ time:"({time}\d+)""",
    """\W({host}[\w\-.]+) CheckPoint""",
    """ src:"({src_ip}[A-Fa-f:\d.]+)""",
    """\Wxlatesrc:"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """ dst:"(0\.0\.0\.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\Wdst:"({dest_translated_ip}[A-Fa-f:\d.]+)""",
    """ xlatedst:"(0\.0\.0\.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\Wdst:"({dest_ip}[A-Fa-f:\d.]+)""",
    """ xlatedst:"({dest_translated_ip}0\.0\.0\.0)""",
    """ service_id:"({app_protocol}[^"]+)""",
    """\Waction:"({action}[^"]+)""",
    """\Wrule:"({rule}[^"]+?)\s*"""",
    """ rule_name:"({rule}[^"]+?)\s*"""",
    """\Wapp_rule_name:"({rule}[^"]+?)\s*"""",
    """ s_port:"({src_port}\d+)""",
    """\Wxlatesport:"({src_translated_port}\d+)""",
    """\Wxlatedport:"({dest_translated_port}\d+)""",
    """ ifdir:"({direction}[^"]+)""",
    """ origin:"({origin_ip}[A-Fa-f:\d.]+)""",
    """ origin_?sic_?name:"CN=({origin_name}[^",]+)""",
    """product:"({product_name}[^"]+)""",
    #slow (15ms -> 8ms)"""\W__policy_id_tag:"({product_name}[^"\[\{]+).+?product:"Log Update"""",
    #slow (15ms -> 8ms)"""product:"Log Update".+?__policy_id_tag:"({product_name}[^"\[\{]+)""",
    """ service:"({dest_port}\d+)""",
    """ proto:"({protocol}[^"]+)""",
    """\Wpeer_gateway:"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """ rule_uid:"\{?({rule_id}[^"\}]+)""",
    """\Wapp_rule_id:"\{({rule_id}[^"\}]+)""",
    """\Wsrc_machine_name:"({src_host}[^"]+?)\s*"""",
    """\Wsrc_machine_name:"({src_host}[^"@]+)@({domain}[^"]+)""",
    """\Wdst_machine_name:"({dest_host}[^"]+?)\s*"""",
    """\Wdst_machine_name:"({dest_host}[^"@]+)@({domain}[^"]+)""",
    """\Wuser:"({user}[^"\(\)@]+?)\s*"""",
    """\Wuser:"({user_email}[^\(\)"@]+@[^\(\)"@]+)\s*"""",
    """\Wsrc_user_name:"(({user}[^"\(\)@]+?)|({user_email}[^"@\(\)]+@[\(\)^"@]+))\s*"""",
    """\Wdst_user_name:"(({user}[^"\(\)@]+?)|({user_email}[^"@]+@[^"@]+))\s*"""",
    """\Wuser:"({user_lastname}[^,"]+),\s*({user_firstname}[\w\s]+\S)\s*\(({account}[^"]+?)\)""",
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s+({user_lastname}[^\s,\(]+)\s*\(({account}[^"]+?)\)""",
    """\Wuser:"({user_lastname}[^,"\(]+),\s*({user_firstname}[\w\s]+\S)\s*\([^\)]+?\)[^"]+?\(({user}[^"@\)]+?)(@({domain}[^"\)]+?))?\)"""
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s+({user_lastname}[^\s,\(]+)\s*\([^\)]+?\)[^"]+?\(({user}[^"@\)]+?)(@({domain}[^"\)]+?))?\)"""
    """\Wreceived_bytes:"({bytes_in}\d+)""",
    """\Wsent_bytes:"({bytes_out}\d+)""",
    """\Wifname:"({interface_name}[^"]+)""",
  ]

```
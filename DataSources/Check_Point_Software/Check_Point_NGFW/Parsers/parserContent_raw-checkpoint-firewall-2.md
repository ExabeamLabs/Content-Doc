#### Parser Content
```Java
{
Name = raw-checkpoint-firewall-2
  DataType = "network-connection"
  Conditions = [ """product=VPN-1 & FireWall-1""", """product:""", """action:"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-firewall-1.Fields}[
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s{1,100}({user_lastname}[^\s,\(]+)\s{0,100}\(({user}.+?)(\)|@)"""
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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """ time:"({time}\d{1,100})""",
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
    """\Wrule:"({rule}[^"]+?)\s{0,100}"""",
    """ rule_name:"({rule}[^"]+?)\s{0,100}"""",
    """\Wapp_rule_name:"({rule}[^"]+?)\s{0,100}"""",
    """ s_port:"({src_port}\d{1,100})""",
    """\Wxlatesport:"({src_translated_port}\d{1,100})""",
    """\Wxlatedport:"({dest_translated_port}\d{1,100})""",
    """ ifdir:"({direction}[^"]+)""",
    """ origin:"({origin_ip}[A-Fa-f:\d.]+)""",
    """ origin_?sic_?name:"CN=({origin_name}[^",]+)""",
    """product:"({product_name}[^"]+)""",
    #slow (15ms -> 8ms)"""\W__policy_id_tag:"({product_name}[^"\[\{]+).+?product:"Log Update"""",
    #slow (15ms -> 8ms)"""product:"Log Update".+?__policy_id_tag:"({product_name}[^"\[\{]+)""",
    """ service:"({dest_port}\d{1,100})""",
    """ proto:"({protocol}[^"]+)""",
    """\Wpeer_gateway:"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """ rule_uid:"\{?({rule_id}[^"\}]+)""",
    """\Wapp_rule_id:"\{({rule_id}[^"\}]+)""",
    """\Wsrc_machine_name:"({src_host}[^"]+?)\s{0,100}"""",
    """\Wsrc_machine_name:"({src_host}[^"@]+)@({domain}[^"]+)""",
    """\Wdst_machine_name:"({dest_host}[^"]+?)\s{0,100}"""",
    """\Wdst_machine_name:"({dest_host}[^"@]+)@({domain}[^"]+)""",
    """\Wuser:"({user}[^"\(\)@]+?)\s{0,100}"""",
    """\Wuser:"({user_email}[^\(\)"@]+@[^\(\)"@]+)\s{0,100}"""",
    """\Wsrc_user_name:"(({user}[^"\(\)@]+?)|({user_email}[^"@\(\)]+@[\(\)^"@]+))\s{0,100}"""",
    """\Wdst_user_name:"(({user}[^"\(\)@]+?)|({user_email}[^"@]+@[^"@]+))\s{0,100}"""",
    """\Wuser:"({user_lastname}[^,"]+),\s{0,100}({user_firstname}[\w\s]+\S)\s{0,100}\(({account}[^"]+?)\)""",
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s{1,100}({user_lastname}[^\s,\(]+)\s{0,100}\(({account}[^"]+?)\)""",
    """\Wuser:"({user_lastname}[^,"\(]+),\s{0,100}({user_firstname}[\w\s]+\S)\s{0,100}\([^\)]+?\)[^"]+?\(({user}[^"@\)]+?)(@({domain}[^"\)]+?))?\)"""
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s{1,100}({user_lastname}[^\s,\(]+)\s{0,100}\([^\)]+?\)[^"]+?\(({user}[^"@\)]+?)(@({domain}[^"\)]+?))?\)"""
    """\Wreceived_bytes:"({bytes_in}\d{1,100})""",
    """\Wsent_bytes:"({bytes_out}\d{1,100})""",
    """\Wifname:"({interface_name}[^"]+)""",
  ]

```
#### Parser Content
```Java
{
Name = raw-checkpoint-firewall-2
  DataType = "network-connection"
  Conditions = [ """product=VPN-1 & FireWall-1""", """product:""", """action:"""" ]
  Fields = ${CheckpointParserTemplates.checkpoint-firewall-1.Fields}[
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s+({user_lastname}[^\s,\(]+)\s*\(({user}.+?)(\)|@)"""
  ] 
}
checkpoint-firewall-1 = {
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wtime:"({time}\d+)""",
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wsrc:"({src_ip}[A-Fa-f:\d.]+)""",
    """\Wxlatesrc:"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """\Wdst:"(0\.0\.0\.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\Wdst:"({dest_translated_ip}[A-Fa-f:\d.]+).+?xlatedst:"(0\.0\.0\.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\Wdst:"({dest_ip}[A-Fa-f:\d.]+).+?xlatedst:"({dest_translated_ip}0\.0\.0\.0)""",
    """\Wservice_id:"({app_protocol}[^"]+)""",
    """\Waction:"({action}[^"]+)""",
    """\Wrule:"({rule}[^"]+?)\s*"""",
    """\Wrule_name:"({rule}[^"]+?)\s*"""",
    """\Wapp_rule_name:"({rule}[^"]+?)\s*"""",
    """\Ws_port:"({src_port}\d+)""",
    """\Wxlatesport:"({src_translated_port}\d+)""",
    """\Wxlatedport:"({dest_translated_port}\d+)""",
    """\Wifdir:"({direction}[^"]+)""",
    """\Worigin:"({origin_ip}[^"]+)""",
    """\Worigin_?sic_?name:"CN=({origin_name}[^",]+)""",
    """product:"({product}[^"]+)""",
    #slow (15ms -> 8ms)"""\W__policy_id_tag:"({product}[^"\[\{]+).+?product:"Log Update"""",
    #slow (15ms -> 8ms)"""product:"Log Update".+?__policy_id_tag:"({product}[^"\[\{]+)""",
    """\Wservice:"({dest_port}\d+)""",
    """\Wproto:"({protocol}[^"]+)""",
    """\Wpeer_gateway:"({src_translated_ip}[A-Fa-f:\d.]+)""",
    """\Wrule_uid:"\{?({rule_id}[^"\}]+)""",
    """\Wapp_rule_id:"\{({rule_id}[^"\}]+)""",
    """\Wsrc_machine_name:"({src_host}[^"]+?)\s*"""",
    """\Wsrc_machine_name:"({src_host}[^"@]+)@({domain}[^"]+)""",
    """\Wdst_machine_name:"({dest_host}[^"]+?)\s*"""",
    """\Wdst_machine_name:"({dest_host}[^"@]+)@({domain}[^"]+)""",
    """\Wuser:"({user}[^"\(\)@]+?)\s*"""",
    """\Wuser:"({user_email}[^\(\)"@]+@[^\(\)"@]+)\s*"""",
    """\Wsrc_user_name:"(({user}[^"\(\)@]+?)|({user_email}[^"@\(\)]+@[\(\)^"@]+))\s*"""",
    """\Wdst_user_name:"(({user}[^"\(\)@]+?)|({user_email}[^"@]+@[^"@]+))\s*"""",
    """\Wuser:"({user_lastname}[^,"]+),\s*({user_firstname}[\w\s]+\S)\s*\(({account}.+?)\)""",
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s+({user_lastname}[^\s,\(]+)\s*\(({account}.+?)\)""",
    """\Wuser:"({user_lastname}[^,"\(]+),\s*({user_firstname}[\w\s]+\S)\s*\([^\)]+?\)[^"]+?\(({user}[^"@\)]+?)(@({domain}[^"\)]+?))?\)"""
    """\Wuser:"({user_firstname}[\w\s]+[^\s,\(])\s+({user_lastname}[^\s,\(]+)\s*\([^\)]+?\)[^"]+?\(({user}[^"@\)]+?)(@({domain}[^"\)]+?))?\)"""
    """\Wreceived_bytes:"({bytes_in}\d+)""",
    """\Wsent_bytes:"({bytes_out}\d+)""",
    """\Wifname:"({interface_name}[^"]+)""",
  ]

```
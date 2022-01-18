#### Parser Content
```Java
{
Name = leef-checkpoint-firewall-2
  Conditions = [ """LEEF""", """|Application Control AND URL Filtering|""" ]

leef-checkpoint-firewall = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=[^@]{1,2000}@\s{0,100}({host}[\w\-.]{1,2000})""",
    """\Worigin=({host}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Worigin_sic_name=CN\\=({origin_sic_name}[^,\s]{1,2000}),""",
    """\Wcat=({action}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\WdevTime=({time}\d{1,100})""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\Wservice=({dest_port}\d{1,100})""",
    """\Wifdir=({direction}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wifname=({src_interface}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Winzone=({inzone}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Woutzone=({outzone}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wproto=({protocol}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wrule=({rule_num}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wrule_name=\s{0,100}({rule}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wrule_uid=({rule_id}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrule_uid=\{({rule_id}.+?)\}""",
    """\Wloguid=\{({log_uid}.+?)\}""",
    """\Wservice_id=({service_id}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wpeer_gateway=({peer_gateway}.+?)(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wsrc_machine_name=({src_host}[^@=]{1,2000}?)(@({domain}.+?))?(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wdst_machine_name=({dest_host}[^@=]{1,2000}?)(@({domain}.+?))?(\s{1,100}\w+:?=|\s{0,100}$)""",
    """\Wdst_user_name=({user_fullname}.+?)\s{0,100}\(\s{0,100}({user}.+?)\s{0,100}\)""",
    """\Wsrc_user_name=({user_fullname}.+?)\s{0,100}\(\s{0,100}({user}.+?)\s{0,100}\)""",
    """\WusrName =({user_fullname}.+?)\s{0,100}\(\s{0,100}({user}.+?)\s{0,100}\)""",
    """LEEF:([^\|]{0,2000}\|){2}({product_name}[^\|]{1,2000})\|[^\|]{0,2000}\|({action}[^\|]{1,2000})""",
    """\Wrule_action=({outcome}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  
}
```
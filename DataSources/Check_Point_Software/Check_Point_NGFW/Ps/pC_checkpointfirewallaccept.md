#### Parser Content
```Java
{
Name = checkpoint-firewall-accept
  DataType = "network-connection"
  Conditions = [ """Product=VPN-1 & FireWall-1""" , """Action=accept""" ]

checkpoint-firewall = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "epoch_sec"
  IsHVF = true
  Fields = [
    """exabeam_indexTime=({time}\d{10})""",
    """\s({host}[\w\-\.]{1,2000})\s{1,100}product:\s{0,100}VPN-1 & FireWall-1;""",
    """\s({action}\w+)\s{1,100}\S+\s{1,100}product:\s{0,100}VPN-1 & FireWall-1;""",
    """logger:\s{0,100}\d\d:\d\d:\d\d\s{0,100}({action}\w+)\s{0,100}({host}[\w.\-]{1,2000})""",
    """({product_name}VPN-1 & FireWall-1);""",
    """\Wdate=\s{0,100}({time}\d{10})[;\]]""",
    """\Wsrc:\s{0,100}(|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}));""",
    """\Ws_port:\s{0,100}(|({src_port}\d{1,100}));""",
    """\Wdst:\s{0,100}(|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}));""",
    """\Wservice:\s{0,100}(|({dest_port}\d{1,100}));""",
    """\Wproto:\s{0,100}(|({protocol}.+?));""",
    """\Wrule:\s{0,100}(|({rule}.+?));""",
    """\Wrule_name:\s{0,100}(|({rule}.+?));""",
    """\Wuser:\s{0,100}(|({user}.+?));""",
    """\Wuser:\s{0,100}({user_fullname}.+?)\s{0,100}\(({account}.+?)\)""",
    """\Wsrc_machine_name:\s{0,100}({user_email}[^;]{1,2000}@[^;]{1,2000}?);""",
    """\Wpolicy_name=\s{0,100}(|({policy}.+?))[;\]]""",
    """\Wi/f_dir:\s{0,100}(|({direction}.+?));""",
    """\Wxlatesrc:\s{0,100}(|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}));""",
    """\Wxlatesport:\s{0,100}(|({src_translated_port}\d{1,100}));""",
    """\Wxlatedst:\s{0,100}(|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}));""",
    """\Wxlatedport:\s{0,100}(|({dest_translated_port}\d{1,100}));""",
    """\Wservice_id:\s{0,100}(|({protocol}.+?));""",
  ]
   DupFields = [ "action->event_name" 
}
```
#### Parser Content
```Java
{
Name = raw-checkpoint-firewall-allow
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  TimeFormat = "epoch_sec"
  IsHVF = true
  DataType = "network-connection"
  Conditions = [ """logger:""", """product:""", """ allow """ ]
  Fields = [
    """exabeam_indexTime=({time}\d{10})""",
    """logger:\s{0,100}\d\d:\d\d:\d\d\s{0,100}({action}\w+)\s{0,100}({host}[\w.\-]{1,2000})""",
    """product:\s{0,100}({product_name}.+?);""",
    """\Wsrc:\s{0,100}(|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}));""",
    """\Ws_port:\s{0,100}(|({src_port}\d{1,100}));""",
    """\Wdst:\s{0,100}(|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}));""",
    """\Wservice:\s{0,100}(|({dest_port}\d{1,100}));""",
    """\Wproto:\s{0,100}(|({protocol}.+?));""",
    """\Wrule:\s{0,100}(|({rule}.+?));""",
    """\Wrule_name:\s{0,100}(|({rule}.+?));""",
    """\Wuser:\s{0,100}(|({user}.+?));""",
    """\Wuser:\s{0,100}({user_fullname}.+?)\s{0,100}\(({account}.+?)\)""",
    """\Wsrc_machine_name:\s{0,100}({user_email}.+?);""",
    """\Wxlatesrc:\s{0,100}(|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}));""",
    """\Wxlatesport:\s{0,100}(|({src_translated_port}\d{1,100}));""",
    """\Wxlatedst:\s{0,100}(|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}));""",
    """\Wxlatedport:\s{0,100}(|({dest_translated_port}\d{1,100}));""",
    """\Wservice_id:\s{0,100}(|({protocol}.+?));""",
  ]
   DupFields = [ "action->event_name" ]
}
```
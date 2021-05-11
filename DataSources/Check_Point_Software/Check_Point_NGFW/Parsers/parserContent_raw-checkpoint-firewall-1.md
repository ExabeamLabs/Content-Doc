#### Parser Content
```Java
{
Name = raw-checkpoint-firewall-1
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  IsHVF = true
  Conditions = [ """ProductName: VPN-1 & FireWall-1;""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}((\+|\-)\d\d:\d\d)?)""",
    """({host}[\w.\-]+)\s{1,100}CPLogToSyslog:""",
    """\WOriginSicName:\s{0,100}CN=({host}[\w.\-]+),O="""
    """\WAction:\s{0,100}(|({action}[^;]+?));""",
    """\Wservice_id:\s{0,100}(|({protocol}[^;]+?));""",
    """\WIfDir:\s{0,100}(|({direction}[^;]+?));""",
    """\Wuser:\s{0,100}(|({user}[^\(\);]+?));""",
    """\Wuser:\s{0,100}({user_fullname}.+?)\s{0,100}\(({account}.+?)\)""",
    """\Wsrc:\s{0,100}(|({src_ip}[a-fA-F\d.:]+));""",
    """\Wdst:\s{0,100}(|({dest_ip}[a-fA-F\d.:]+));""",
    """\Wxlatesrc:\s{0,100}(|({src_translated_ip}[a-fA-F\d.:]+));""",
    """\Wrule_name:\s{0,100}(|({rule}[^;]+?));""",
    """\WProductName:\s{0,100}(|({app}[^;]+?));""",
    """\Wsvc:\s{0,100}({dest_port}\d{1,100})""",
    """\Wsport_svc:\s{0,100}({src_port}\d{1,100})""",
  ]
   DupFields = [ "action->event_name" ]
}
```
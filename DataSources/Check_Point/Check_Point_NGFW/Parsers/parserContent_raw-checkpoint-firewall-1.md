#### Parser Content
```Java
{
Name = raw-checkpoint-firewall-1
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  IsHVF = true
  Conditions = [ """ProductName: VPN-1 & FireWall-1;""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+((\+|\-)\d\d:\d\d)?)""",
    """({host}[\w.\-]+)\s+CPLogToSyslog:""",
    """\WOriginSicName:\s*CN=({host}[\w.\-]+),O="""
    """\WAction:\s*(|({action}[^;]+?));""",
    """\Wservice_id:\s*(|({protocol}[^;]+?));""",
    """\WIfDir:\s*(|({direction}[^;]+?));""",
    """\Wuser:\s*(|({user}[^\(\);]+?));""",
    """\Wuser:\s*({user_fullname}.+?)\s*\(({account}.+?)\)""",
    """\Wsrc:\s*(|({src_ip}[a-fA-F\d.:]+));""",
    """\Wdst:\s*(|({dest_ip}[a-fA-F\d.:]+));""",
    """\Wxlatesrc:\s*(|({src_translated_ip}[a-fA-F\d.:]+));""",
    """\Wrule_name:\s*(|({rule}[^;]+?));""",
    """\WProductName:\s*(|({app}[^;]+?));""",
    """\Wsvc:\s*({dest_port}\d+)""",
    """\Wsport_svc:\s*({src_port}\d+)""",
  ]
   DupFields = [ "action->event_name" ]
}
```
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
    """({host}[\w.\-]{1,2000})\s{1,100}CPLogToSyslog:""",
    """\WOriginSicName:\s{0,100}CN=({host}[\w.\-]{1,2000}),O="""
    """\WAction:\s{0,100}(|({action}[^;]{1,2000}?));""",
    """\Wservice_id:\s{0,100}(|({protocol}[^;]{1,2000}?));""",
    """\WIfDir:\s{0,100}(|({direction}[^;]{1,2000}?));""",
    """\Wuser:\s{0,100}(|({user}[^\(\);]{1,2000}?));""",
    """\Wuser:\s{0,100}({user_fullname}.+?)\s{0,100}\(({account}.+?)\)""",
    """\Wsrc:\s{0,100}(|({src_ip}[a-fA-F\d.:]{1,2000}));""",
    """\Wdst:\s{0,100}(|({dest_ip}[a-fA-F\d.:]{1,2000}));""",
    """\Wxlatesrc:\s{0,100}(|({src_translated_ip}[a-fA-F\d.:]{1,2000}));""",
    """\Wrule_name:\s{0,100}(|({rule}[^;]{1,2000}?));""",
    """\WProductName:\s{0,100}(|({app}[^;]{1,2000}?));""",
    """\Wsvc:\s{0,100}({dest_port}\d{1,100})""",
    """\Wsport_svc:\s{0,100}({src_port}\d{1,100})""",
  ]
   DupFields = [ "action->event_name" ]
}
```
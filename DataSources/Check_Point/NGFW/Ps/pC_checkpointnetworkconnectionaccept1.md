#### Parser Content
```Java
{
Name = checkpoint-network-connection-accept-1
  Vendor = Check Point
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ CheckPoint """, """ origin:""", """product=VPN-1 & FireWall-1""", """action:Accept";""" ]
  Fields = [
    """\Wtime:({time}\d{1,100})""",
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """src_machine_name:({src_host}[^"]{1,2000})""",
    """\Wsrc:({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wxlatesrc:(0\.0\.0\.0|({src_translated_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wdst:({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wxlatedst:(0\.0\.0\.0|({dest_translated_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Wservice_id:({app_protocol}[^"\;]{1,2000})""",
    """\Waction:({action}Accept)""",
    """\Wrule_name:({rule}[^"\;]{1,2000}?)\s{0,100}";""",
    """\Ws_port:({src_port}\d{1,100})""",
    """\Wxlatesport:({src_translated_port}\d{1,100})""",
    """\Wxlatedport:({dest_translated_port}\d{1,100})""",
    """\Wifdir:({direction}[^"]{1,2000})""",
    """\Wservice:({dest_port}\d{1,100})""",
    """\Wproto:({protocol}[^"\;]{1,2000})""",
    """\Wrule_uid:\{?({rule_id}[^"\}\;]{1,2000})""",
  ]
  DupFields = [ "action->event_name" ]


}
```
#### Parser Content
```Java
{
Name = checkpoint-firewall-allow-2
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """CheckPoint""", """product:""", """action:\"Allow\"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\Wtime:\\"({time}\d{1,100})""",
    """\W({host}[\w\-.]{1,2000}) CheckPoint""",
    """\Wsrc:\\"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wdst:\\"(0\.0\.0\.0|({dest_ip}[A-Fa-f:\d.]{1,2000}))""",
    """\Waction:\\"({action}[^"\\]{1,2000})""",
    """\Ws_port:\\"({src_port}\d{1,100})""",
    """\Wifdir:\\"({direction}[^"\\]{1,2000})""",
    """\Worigin:\\"({origin_ip}[^"\\]{1,2000})""",
    """\Worigin_?sic_?name:\\"CN=({origin_name}[^",\\]{1,2000})""",
    """product:\\"({product_name}[^"\\]{1,2000})""",
    """\Wservice:\\"({dest_port}\d{1,100})""",
    """\Wproto:\\"({protocol}[^"\\]{1,2000})""",
    """\Wapp_rule_id:\\"\{({rule_id}[^"\}\\]{1,2000})""",
    """\Wifname:\\"({interface_name}[^"\\]{1,2000})""",
    """\Wweb_client_type:\\"Other:\s{0,100}({user_agent}[^"\\]{1,2000})""",
    """"(?:-|Mozilla\/[^"]{1,2000}\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]{1,2000}?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  ]
  DupFields = [ "action->event_name", "action->outcome" ]
}
```
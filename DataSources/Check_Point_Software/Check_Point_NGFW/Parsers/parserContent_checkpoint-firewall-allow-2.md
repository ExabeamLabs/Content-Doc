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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """\Wtime:\\"({time}\d{1,100})""",
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wsrc:\\"({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst:\\"(0\.0\.0\.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\Waction:\\"({action}[^"\\]+)""",
    """\Ws_port:\\"({src_port}\d{1,100})""",
    """\Wifdir:\\"({direction}[^"\\]+)""",
    """\Worigin:\\"({origin_ip}[^"\\]+)""",
    """\Worigin_?sic_?name:\\"CN=({origin_name}[^",\\]+)""",
    """product:\\"({product_name}[^"\\]+)""",
    """\Wservice:\\"({dest_port}\d{1,100})""",
    """\Wproto:\\"({protocol}[^"\\]+)""",
    """\Wapp_rule_id:\\"\{({rule_id}[^"\}\\]+)""",
    """\Wifname:\\"({interface_name}[^"\\]+)""",
    """\Wweb_client_type:\\"Other:\s{0,100}({user_agent}[^"\\]+)""",
    """"(?:-|Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  ]
  DupFields = [ "action->event_name", "action->outcome" ]
}
```
#### Parser Content
```Java
{
Name = checkpoint-firewall-allow-2
  Vendor = Check Point
  Product = Check Point NGFW
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """CheckPoint""", """product:""", """action:\"Allow\"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """\Wtime:\\"({time}\d+)""",
    """\W({host}[\w\-.]+) CheckPoint""",
    """\Wsrc:\\"({src_ip}[A-Fa-f:\d.]+)""",
    """\Wdst:\\"(0\.0\.0\.0|({dest_ip}[A-Fa-f:\d.]+))""",
    """\Waction:\\"({action}[^"\\]+)""",
    """\Ws_port:\\"({src_port}\d+)""",
    """\Wifdir:\\"({direction}[^"\\]+)""",
    """\Worigin:\\"({origin_ip}[^"\\]+)""",
    """\Worigin_?sic_?name:\\"CN=({origin_name}[^",\\]+)""",
    """product:\\"({product}[^"\\]+)""",
    """\Wservice:\\"({dest_port}\d+)""",
    """\Wproto:\\"({protocol}[^"\\]+)""",
    """\Wapp_rule_id:\\"\{({rule_id}[^"\}\\]+)""",
    """\Wifname:\\"({interface_name}[^"\\]+)""",
    """\Wweb_client_type:\\"Other:\s*({user_agent}[^"\\]+)""",
    """"(?:-|Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident))""",
  ]
  DupFields = [ "action->event_name", "action->outcome" ]
}
```
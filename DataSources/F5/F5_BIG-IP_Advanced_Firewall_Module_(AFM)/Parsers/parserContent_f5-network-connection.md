#### Parser Content
```Java
{
Name = f5-network-connection
  Vendor = F5
  Product = F5 BIG-IP Advanced Firewall Module (AFM)
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """device_vendor="F5"""", """translated_vlan="""", """acl_policy_type="""" ]
  Fields = [
    """\Wacl_rule_name="({rule}[^"]+)""",
    """\Waction="({action}[^"]+)""",
    """\Whostname="({host}[^"]+)""",
    """\Wdest_ip="({dest_ip}[a-fA-F\d.:]+)""",
    """\Wdest_port="({dest_port}\d{1,100})""",
    """\Wsource_ip="({src_ip}[a-fA-F\d.:]+)""",
    """\Wsource_port="({src_port}\d{1,100})""",
    """\Wdate_time="({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """\Wtranslated_dest_ip="({dest_translated_ip}[a-fA-F\d.:]+)""",
    """\Wtranslated_dest_port="({dest_translated_port}\d{1,100})""",
    """\Wtranslated_source_ip="({src_translated_ip}[a-fA-F\d.:]+)""",
    """\Wtranslated_source_port="({src_translated_port}\d{1,100})""",
    """\Wip_protocol="({protocol}[^"]+)""",
    """\Werrdefs_msg_name="({event_name}[^"]+)""",
  ]
}
```
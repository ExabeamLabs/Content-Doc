#### Parser Content
```Java
{
Name = meraki-ip-flow-start
  Vendor = Cisco
  Product = Cisco Meraki MX appliances
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "epoch_sec"
  Conditions = [ """ ip_flow_start""", """ src=""", """ dst=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """(<\d+>[^\s]+)?\s+({time}\d+)\.\d+\s({event_name}[^\s]+?)\ssrc=""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sdst=({dest_ip}[a-fA-F\d.:]+)""",
    """\sprotocol=({protocol}\w+)""",
    """\ssport=({src_port}\d+)""",
    """\sdport=({dest_port}\d+)""",
    """\smac=({src_mac}[a-fA-F\d.:]+)""",
    """\stranslated_src_ip=({src_translated_ip}[a-fA-F\d.:]+)\stranslated_port=({src_translated_port}\d+)""",
    """\stranslated_dst_ip=({dest_translated_ip}[a-fA-F\d.:]+)\stranslated_port=({dest_translated_port}\d+)""",
  ]
}
```
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
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """(<\d{1,100}>[^\s]{1,2000})?\s{1,100}({time}\d{1,100})\.\d{1,100}\s({event_name}[^\s]{1,2000}?)\ssrc=""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sprotocol=({protocol}\w+)""",
    """\ssport=({src_port}\d{1,100})""",
    """\sdport=({dest_port}\d{1,100})""",
    """\smac=({src_mac}[a-fA-F\d.:]{1,2000})""",
    """\stranslated_src_ip=({src_translated_ip}[a-fA-F\d.:]{1,2000})\stranslated_port=({src_translated_port}\d{1,100})""",
    """\stranslated_dst_ip=({dest_translated_ip}[a-fA-F\d.:]{1,2000})\stranslated_port=({dest_translated_port}\d{1,100})""",
  ]
}
```
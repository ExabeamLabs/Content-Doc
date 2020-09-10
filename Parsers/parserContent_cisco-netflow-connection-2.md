#### Parser Content
```Java
{
Name = cisco-netflow-connection-2
  Vendor = Cisco
  Product = Cisco Netflow
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ t_int=""", """ nfc_id=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+ \d\d \d\d:\d\d:\d\d ({host}[\w.\-]+)""",
    """\ssrc_ip=({src_ip}[a-fA-F\d.:]+)""",
    """\ssrc_host=(unknown|({src_host}.+?))(\s+\w+=|\s*$)""",
    """\ssrc_port=({src_port}\d+)""",
    """\sdest_ip=({dest_ip}[a-fA-F\d.:]+)""",
    """\sdest_host=(unknown|({dest_host}.+?))(\s+\w+=|\s*$)""",
    """\sdest_port=({dest_port}\d+)""",
    """\stcp_flag="({tcp_flags}[^"]+)""",
    """\spackets_in=({packets_in}\d+)""",
    """\sbytes_in=({bytes_in}\d+)""",
    """\spackets_out=({packets_out}\d+)""",
    """\sbytes_out=({bytes_out}\d+)""",
    """\sprotocol=({protocol}\d+)""",
  ]
  DupFields = [ "bytes_in->bytes", "packets_in->packets"  ]
}
```
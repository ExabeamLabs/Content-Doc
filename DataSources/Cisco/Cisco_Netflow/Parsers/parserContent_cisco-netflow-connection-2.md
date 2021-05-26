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
    """\w+ \d\d \d\d:\d\d:\d\d ({host}[\w.\-]{1,2000})""",
    """\ssrc_ip=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\ssrc_host=(unknown|({src_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssrc_port=({src_port}\d{1,100})""",
    """\sdest_ip=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdest_host=(unknown|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdest_port=({dest_port}\d{1,100})""",
    """\stcp_flag="({tcp_flags}[^"]{1,2000})""",
    """\spackets_in=({packets_in}\d{1,100})""",
    """\sbytes_in=({bytes_in}\d{1,100})""",
    """\spackets_out=({packets_out}\d{1,100})""",
    """\sbytes_out=({bytes_out}\d{1,100})""",
    """\sprotocol=({protocol}\d{1,100})""",
  ]
  DupFields = [ "bytes_in->bytes", "packets_in->packets"  ]
}
```
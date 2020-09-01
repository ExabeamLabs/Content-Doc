#### Parser Content
```Java
{
Name = json-cisco-netflow-connection
  Vendor = Cisco
  Product = Cisco Netflow
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MMM-dd HH:mm:ss"
  Conditions = [ """"bytes_in":""", """"exporter_time":"""", """"packets_in":""", """"tcp_flags":""", """"flow_start_time":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"exporter_time":"({time}\d+-\w+-\d+\s+\d+:\d+:\d+)""",
    """"bytes_in":({bytes_in}\d+)""",
    """"bytes_out":({bytes_out}\d+)""",
    """"dest_ip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"dest_port":({dest_port}\d+)""",
    """"flow_end_time":({flow_end_time}\d+)""",
    """"flow_start_time":({flow_start_time}\d+)""",
    """"packets_in":({packets_in}\d+)""",
    """"packets_out":({packets_out}\d+)""",
    """"protoid":({protocol}\d+)""",
    """"src_ip":"({src_ip}[A-Fa-f:\d.]+)""",
    """"src_port":({src_port}\d+)""",
    """"tcp_flags":({tcp_flags}\d+)""",
  ]
  DupFields = [ "bytes_in->bytes", "packets_in->packets"]
}

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
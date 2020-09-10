#### Parser Content
```Java
{
Name = cisco-netflow-connection
  Vendor = Cisco
  Product = Cisco Netflow
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """6-IPACCESSLOG""", """ packet""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\S+\s+){1,2}(\w+\s+\d+ \d\d:\d\d:\d\d(\.\d+)?)\s+\S+\s+\S+-6-IPACCESSLOG""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """list \S+ ({outcome}\S+) ({protocol}\S+) ({src_ip}[a-fA-F\d.:]+)(?:\(({src_port}\d+)\)||\s*({src_interface}\S+))\s*->\s*({dest_ip}[a-fA-F\d.:]+)(?:\(({dest_port}\d+)\))?""",
    """({packets}\d+)\s+packets?\s*$""",
  ]
}

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
  DupFields = [ "bytes_in->bytes", "packets_in->packets"  ]
}

{
  Name = q-cisco-dns-response
  Vendor = Cisco
  Product = OpenDNS Umbrella
  Lms = QRadar
  DataType = "dns-response"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"MostGranularIdentity"""", """"Identities"""", """"QueryType"""", """"ResponseCode"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"Timestamp"*:"*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Identities"*:"*({identities}[^"]+)""",
    """"InternalIp"*:"*({dest_ip}[^"]+)""",
    """"ExternalIp"*:"*({src_ip}[^"]+)""",
    """"Action"*:"*({outcome}[^"]+)""",
    """"QueryType"*:"*({query_type}[^"]+)""",
    """"ResponseCode"*:"*({dns_response_code}[^"]+)""",
    """"Domain"*:"*({query}[^"]+)""",
    """"Categories"*:"*({category}[^"]+)""",
  ]
}
```
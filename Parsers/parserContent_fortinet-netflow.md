#### Parser Content
```Java
{
Name = fortinet-netflow
  Vendor = Fortinet
  Product = Fortinet Enterprise Firewall
  Lms = Splunk
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """first_switched""" , """traffic_locality""" ]
  Fields = [
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """\Wip_protocol"*:"*\s*({protocol}[^",]*?)\s*("|,)""",
     """\Whost"*:"*\s*({host}[\w\-.]*)""",
     """\Wsrc_addr"*:"*\s*({src_ip}[A-Fa-f:\d.]*)""",
     """\Wsrc_port"*:\s*(([A-Fa-f:\d.]+?):)?({src_port}\d+)?\s*("|,|$)""",
     """\Wdst_addr"*:"*\s*({dest_ip}[A-Fa-f:\d.]*)""",
     """\Wdst_port"*:\s*(([A-Fa-f:\d.]+?):)?({dest_port}\d+)?\s*("|,|$)""",
     """\Wdirection"*:"*\s*({direction}[^",]*?)\s*("|,)""",
     """("|:)({time}\d\d\d\d-\d\d-\d\d(T|\s+)\d\d:\d\d:\d\d)""",
     """\Wbytes"*:\s*({bytes}\d+)""",
     """\Wservice_name"*:"*\s*({service}[^("\s]*)""",
     """\Wflow_end_reason"*:\s*({end_reason}\d+)""",
     """\Wfirst_switched"*:"*\s*({time_start}[^",]*?)\s*("|,)""",
     """\Wlast_switched"*:"*\s*({time_end}[^",]*?)\s*("|,)""",
     """\Wpackets"*:\s*({packets}\d+)""",
     """\Wtraffic_locality"*:"*\s*(|({locality}[^",]*?))\s*("|,|$)""",
     """"src_hostname":"({src_host}[^"]+)""",
  ]
}
```
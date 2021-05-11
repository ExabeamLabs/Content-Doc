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
     """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
     """\Wip_protocol"{0,20}:"{0,20}\s{0,100}({protocol}[^",]*?)\s{0,100}("|,)""",
     """\Whost"{0,20}:"{0,20}\s{0,100}({host}[\w\-.]*)""",
     """\Wsrc_addr"{0,20}:"{0,20}\s{0,100}({src_ip}[A-Fa-f:\d.]*)""",
     """\Wsrc_port"{0,20}:\s{0,100}(([A-Fa-f:\d.]+?):)?({src_port}\d{1,100})?\s{0,100}("|,|$)""",
     """\Wdst_addr"{0,20}:"{0,20}\s{0,100}({dest_ip}[A-Fa-f:\d.]*)""",
     """\Wdst_port"{0,20}:\s{0,100}(([A-Fa-f:\d.]+?):)?({dest_port}\d{1,100})?\s{0,100}("|,|$)""",
     """\Wdirection"{0,20}:"{0,20}\s{0,100}({direction}[^",]*?)\s{0,100}("|,)""",
     """("|:)({time}\d\d\d\d-\d\d-\d\d(T|\s{1,100})\d\d:\d\d:\d\d)""",
     """\Wbytes"{0,20}:\s{0,100}({bytes}\d{1,100})""",
     """\Wservice_name"{0,20}:"{0,20}\s{0,100}({service}[^("\s]*)""",
     """\Wflow_end_reason"{0,20}:\s{0,100}({end_reason}\d{1,100})""",
     """\Wfirst_switched"{0,20}:"{0,20}\s{0,100}({time_start}[^",]*?)\s{0,100}("|,)""",
     """\Wlast_switched"{0,20}:"{0,20}\s{0,100}({time_end}[^",]*?)\s{0,100}("|,)""",
     """\Wpackets"{0,20}:\s{0,100}({packets}\d{1,100})""",
     """\Wtraffic_locality"{0,20}:"{0,20}\s{0,100}(|({locality}[^",]*?))\s{0,100}("|,|$)""",
     """"src_hostname":"({src_host}[^"]+)""",
  ]
}
```
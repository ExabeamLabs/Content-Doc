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
     """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
     """\Wip_protocol"{0,20}:"{0,20}\s{0,100}({protocol}[^",]{0,2000}?)\s{0,100}("|,)""",
     """\Whost"{0,20}:"{0,20}\s{0,100}({host}[\w\-.]{0,2000})""",
     """\Wsrc_addr"{0,20}:"{0,20}\s{0,100}({src_ip}[A-Fa-f:\d.]{0,2000})""",
     """\Wsrc_port"{0,20}:\s{0,100}(([A-Fa-f:\d.]{1,2000}?):)?({src_port}\d{1,100})?\s{0,100}("|,|$)""",
     """\Wdst_addr"{0,20}:"{0,20}\s{0,100}({dest_ip}[A-Fa-f:\d.]{0,2000})""",
     """\Wdst_port"{0,20}:\s{0,100}(([A-Fa-f:\d.]{1,2000}?):)?({dest_port}\d{1,100})?\s{0,100}("|,|$)""",
     """\Wdirection"{0,20}:"{0,20}\s{0,100}({direction}[^",]{0,2000}?)\s{0,100}("|,)""",
     """("|:)({time}\d\d\d\d-\d\d-\d\d(T|\s{1,100})\d\d:\d\d:\d\d)""",
     """\Wbytes"{0,20}:\s{0,100}({bytes}\d{1,100})""",
     """\Wservice_name"{0,20}:"{0,20}\s{0,100}({service}[^("\s]{0,2000})""",
     """\Wflow_end_reason"{0,20}:\s{0,100}({end_reason}\d{1,100})""",
     """\Wfirst_switched"{0,20}:"{0,20}\s{0,100}({time_start}[^",]{0,2000}?)\s{0,100}("|,)""",
     """\Wlast_switched"{0,20}:"{0,20}\s{0,100}({time_end}[^",]{0,2000}?)\s{0,100}("|,)""",
     """\Wpackets"{0,20}:\s{0,100}({packets}\d{1,100})""",
     """\Wtraffic_locality"{0,20}:"{0,20}\s{0,100}(|({locality}[^",]{0,2000}?))\s{0,100}("|,|$)""",
     """"src_hostname":"({src_host}[^"]{1,2000})""",
  ]
}
```
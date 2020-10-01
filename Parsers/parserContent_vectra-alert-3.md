#### Parser Content
```Java
{
Name = vectra-alert-3
  Product = Vectra
  Vendor = Vectra
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """vectra_timestamp""","""headend_addr""","""category""","""threat"""]
  Fields =[
    """({time}\d+-\d+-\d+T\d+:\d+:\d+)""",
    """"*d_type_vname"*:\s*"+({alert_name}[^"]+)""",
    """"*dvchost"*:\s*"+({host}[^"]+)""",
    """"*host_ip"*:\s*"+({src_ip}[^"]+)""",
    """"*href"*:\s*"+({malware_url}[^"]+)""",
    """"*detection_id"*:\s+({alert_id}\d+)""",
    """"*dd_bytes_sent"*:\s+({bytes_out}\d+)""",
    """"*dd_dst_port"*:\s+({dest_port}\d+)""",
    """"*category"*:\s+"*({alert_type}[^"]+)""",
    """"*dd_bytes_rcvd"*:\s+({bytes_in}\d+)""",
    """"*dd_dst_dns"*:\s+"+({web_domain}[^"]+)"+,""",
    """"*severity"*:\s+({alert_severity}\d+)""",
    """"*host_name"*:\s+"+({src_host}[^"]+)""",
    """"*dd_dst_ip"*:\s+"+({dest_ip}[^"]+)""",
    """"*dd_proto"*:\s+"+({protocol}[^"]+)"+,""",
    """"*threat"*:\s+({threat_id}\d+)"""
  ]
 }
```
#### Parser Content
```Java
{
Name = vectra-alert-3
  Product = Vectra Cognito Detect
  Vendor = Vectra
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """vectra_timestamp""","""headend_addr""","""category""","""threat"""]
  Fields =[
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})""",
    """"{0,20}d_type_vname"{0,20}:\s{0,100}"{1,20}({alert_name}[^"]{1,2000})""",
    """"{0,20}dvchost"{0,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})""",
    """"{0,20}host_ip"{0,20}:\s{0,100}"{1,20}({src_ip}[^"]{1,2000})""",
    """"{0,20}href"{0,20}:\s{0,100}"{1,20}({malware_url}[^"]{1,2000})""",
    """"{0,20}detection_id"{0,20}:\s{1,100}({alert_id}\d{1,100})""",
    """"{0,20}dd_bytes_sent"{0,20}:\s{1,100}({bytes_out}\d{1,100})""",
    """"{0,20}dd_dst_port"{0,20}:\s{1,100}({dest_port}\d{1,100})""",
    """"{0,20}category"{0,20}:\s{1,100}"{0,20}({alert_type}[^"]{1,2000})""",
    """"{0,20}dd_bytes_rcvd"{0,20}:\s{1,100}({bytes_in}\d{1,100})""",
    """"{0,20}dd_dst_dns"{0,20}:\s{1,100}"{1,20}({web_domain}[^"]{1,2000})"{1,20}
```
#### Parser Content
```Java
{
Name = cef-netskope-alert
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """CEF:""", """|Skyformation|""", """"alert_type":"""", """destinationServiceName=Netskope""", """"ns_detection_name":"""",  ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]+@[^@"\s]+)|(({domain}[^"@\\\/\s]+)[\\\/]+)?({user}[^"@\\\/\s]+))"""",
    """"app":"({process}[^"]+)""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]+)""",
    """"malware_id":"({alert_id}[^"]+)""",
    """"category":"({threat_category}[^"]+)""",
    """"ns_detection_name":"({alert_name}[^"]+)""",
    """"alert_type":"({alert_type}[^"]+)""",
    """"url":"({malware_url}[^"]+)""",
    """"malware_scanner_result":"({outcome}[^"]+)""",
    """"local_md5":"({md5}[^"]+)""",
    """"malware_severity":"({alert_severity}[^"]+)""",
    """"file_path":"({file_path_at}[^"]+)"""",
    """"shared_with":\[({shared_with_at}[^\]]+)\]""",
    """"local_sha256":"({sha256_at}[^"]+)"""",
    """"site":"({site_at}[^"]+)""""
  ]
  DupFields = ["process->process_name"]
}
```
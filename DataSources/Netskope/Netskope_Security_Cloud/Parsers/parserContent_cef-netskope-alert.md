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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"timestamp":({time}\d{1,100})""",
    """"user":"(({user_email}[^@"\s]{1,2000}@[^@"\s]{1,2000})|(({domain}[^"@\\\/\s]{1,2000})[\\\/]{1,2000})?({user}[^"@\\\/\s]{1,2000}))"""",
    """"app":"({process}[^"]{1,2000})""",
    """"dstip":"({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """"malware_id":"({alert_id}[^"]{1,2000})""",
    """"category":"({threat_category}[^"]{1,2000})""",
    """"ns_detection_name":"({alert_name}[^"]{1,2000})""",
    """"alert_type":"({alert_type}[^"]{1,2000})""",
    """"url":"({malware_url}[^"]{1,2000})""",
    """"malware_scanner_result":"({outcome}[^"]{1,2000})""",
    """"local_md5":"({md5}[^"]{1,2000})""",
    """"malware_severity":"({alert_severity}[^"]{1,2000})""",
    """"file_path":"({file_path_at}[^"]{1,2000})"""",
    """"shared_with":\[({shared_with_at}[^\]]{1,2000})\]""",
    """"local_sha256":"({sha256_at}[^"]{1,2000})"""",
    """"site":"({site_at}[^"]{1,2000})""""
  ]
  DupFields = ["process->process_name"]
}
```
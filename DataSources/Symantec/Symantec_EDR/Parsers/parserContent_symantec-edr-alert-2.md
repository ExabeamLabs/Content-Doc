#### Parser Content
```Java
{
Name = symantec-edr-alert-2
  Vendor = Symantec
  Product = Symantec EDR
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"app_name":""", """"symc_device_action":""", """"sep_mid":"""" ]
  Fields = [
    """"device_time":"({time}[^"]+)"""",
    """"user_name":"({user}[^"]+)"""",
    """"device_name":"({host}[^"]+)"""",
    """"categories":\["({alert_type}[^"]+)"""",
    """"signature_name":"({alert_name}[^"]+)"""",
    """severity":({alert_severity}\d{1,100})""",
    """"host_name":"({src_host}[^"]+)"""",
    """event_id":({alert_id}\d{1,100})""",
    """"app_name":"({malware_url}[^"]+)"""",
    """"domain_name":"({domain}[^"]+)"""",
    """"device_ip":"({dest_ip}[^"]+)"""",
    """"data_source_ip":"({src_ip}[^"]+)"""",
    """"event_desc":"({additional_info}[^"]+)"""",
  ]
}
```
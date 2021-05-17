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
    """"device_time":"({time}[^"]{1,2000})"""",
    """"user_name":"({user}[^"]{1,2000})"""",
    """"device_name":"({host}[^"]{1,2000})"""",
    """"categories":\["({alert_type}[^"]{1,2000})"""",
    """"signature_name":"({alert_name}[^"]{1,2000})"""",
    """severity":({alert_severity}\d{1,100})""",
    """"host_name":"({src_host}[^"]{1,2000})"""",
    """event_id":({alert_id}\d{1,100})""",
    """"app_name":"({malware_url}[^"]{1,2000})"""",
    """"domain_name":"({domain}[^"]{1,2000})"""",
    """"device_ip":"({dest_ip}[^"]{1,2000})"""",
    """"data_source_ip":"({src_ip}[^"]{1,2000})"""",
    """"event_desc":"({additional_info}[^"]{1,2000})"""",
  ]
}
```
#### Parser Content
```Java
{
Name = mcafee-network-alert
  Vendor = McAfee
  Product = McAfee Network Security Platform (IPS)
  DataType = network-alert
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""threat_source_ip_address""" , """McAfee Host Intrusion Prevention"""]
  Fields = [
    """"event_generated_time":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """"action_taken":"({outcome}[^"]{1,2000})"""", 
    """"detecting_product_ipv4_address":"({host}[^"]{1,2000})"""",
    """"detecting_product_host_name":"({host}[^"]{1,2000})"""",
    """"threat_source_ip_address":"({src_ip}[^"]{1,2000})"""",
    """"threat_target_ip_address":"({dest_ip}[^"]{1,2000})"""",
    """"threat_source_user_name":"({domain}[^\\]{1,2000})\\+({user}[^"]{1,2000})"""",
    """"threat_severity":"({alert_severity}[^"]{1,2000})"""",
    """"threat_source_process_name":"\w+:\\+([^\\"]{1,2000}\\+)+({process_name}[^"]{1,2000})"""",
    """"signature_name_host_ips":"({alert_name}[^"]{1,2000})"""",
    """"event_description":"({alert_type}[^"]{1,2000})"""",
    """"threat_source_host_name":"({src_host}[^"]{1,2000})"""",
    """"event_category":"({alert_type}[^"]{1,2000})"""",
    """"threat_target_host_name":"({dest_host}[^"]{1,2000})"""",
    """"threat_type":"({additional_info}[^"]{1,2000})""""
  ]
}
```
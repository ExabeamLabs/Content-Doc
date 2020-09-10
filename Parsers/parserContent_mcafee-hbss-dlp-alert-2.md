#### Parser Content
```Java
{
Name = mcafee-hbss-dlp-alert-2
  Vendor = McAfee
  Product = McAfee Advanced Threat Defense
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "YYYY-MM-dd HH:mm:ss"
  Conditions = [""""detecting_product_name":"MSME"""" , """threat_source_process_name""" , """threat_handled"""]
  Fields = [
    """event_generated_time":"({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """"threat_source_user_name":"({user_email}[^"]+)"""",
    """"threat_target_user_name":"({target}[^"]+)"""",
    """"detecting_product_ip_address":"({host}[^"]+)"""",
    """"detecting_product_host_name":"({host}[^"]+)"""",
    """"threat_severity":"({alert_severity}[^"]+)"""",
    """"event_category":"({alert_type}[^"]+)"""",
    """"threat_source_process_name":"({process}[^"]+)"""",
    """"action_taken":"({outcome}[^"]+)"""",
    """"threat_type":"({alert_name}[^"]+)"""",
  ]
}
```
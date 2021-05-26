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
    """"threat_source_user_name":"({user_email}[^"]{1,2000})"""",
    """"threat_target_user_name":"({target}[^"]{1,2000})"""",
    """"detecting_product_ip_address":"({host}[^"]{1,2000})"""",
    """"detecting_product_host_name":"({host}[^"]{1,2000})"""",
    """"threat_severity":"({alert_severity}[^"]{1,2000})"""",
    """"event_category":"({alert_type}[^"]{1,2000})"""",
    """"threat_source_process_name":"({process}[^"]{1,2000})"""",
    """"action_taken":"({outcome}[^"]{1,2000})"""",
    """"threat_type":"({alert_name}[^"]{1,2000})"""",
  ]
}
```
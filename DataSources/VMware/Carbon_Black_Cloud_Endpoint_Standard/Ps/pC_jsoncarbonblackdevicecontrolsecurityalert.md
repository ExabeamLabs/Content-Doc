#### Parser Content
```Java
{
Name = json-carbonblack-device-control-security-alert
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"type":"DEVICE_CONTROL"""", """"state":"OPEN"""", """"threat_id":""", """"alert_url":"""" ]
  Fields = [
    """"first_event_time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,1000})""",
    """"device_username":"(({domain}[^\\]{1,1000})\\{1,10})?({user}[^"]{1,1000})"""",
    """"device_name":"({src_host}[^"]{1,1000})"""",
    """"policy_name":"({alert_name}[^"]{1,2000})"""",
    """"severity":({alert_severity}\d{1,100})""",
    """"reason":"({additional_info}[^"]{1,2000})"""",
    """"device_internal_ip":"({src_ip}[a-fA-F\d.:]{1,1000})"""",
    """"device_external_ip":"({dest_ip}[a-fA-F\d.:]{1,1000})"""",
    """"threat_cause_vector":"({alert_type}[^"]{1,2000})"""",
    """"sensor_action":"({action}[^"]{1,2000})"""",
    """"alert_url":"({malware_url}[^"]{1,2000})"""", 
    """"threat_id":"({alert_id}[^"]{1,1000})""""
  ]


}
```
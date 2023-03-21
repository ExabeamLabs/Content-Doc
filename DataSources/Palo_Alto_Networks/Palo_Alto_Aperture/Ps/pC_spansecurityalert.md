#### Parser Content
```Java
{
Name = s-pan-security-alert
    Vendor = Palo Alto Networks
    Product = Palo Alto Aperture
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """"incident"""", """"cloud_app_instance"""", """"item_owner":"""", """"item_creator_email":""", """"item_verdict":"malware"""" ]
    Fields = [
	  """exabeam_host=({host}[^\s]{1,2000})""",
	  """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
	  """"policy_rule_name":"({alert_name}[^"]{1,2000})"""",
	  """"item_verdict":"({alert_type}[^"]{1,2000})"""",
	  """"severity":({alert_severity}[\d\.]{1,100})""",
	  """"item_creator":"(Possible External Application Or Not Logged In User|({user_fullname}[^"]{1,2000}))"""",
	  """"item_creator_email":"(Unknown|({user_email}[^\s",@]{1,2000}\@[\w\.\-]{1,2000}))"""",
	  """"item_name":"({file_name}[^"]{1,2000})"""",
          """"item_cloud_url":"({malware_url}[^"]{1,2000})"""",
          """"incident_id":"({alert_id}[^"]{1,100})"""",
	  """"item_sha256":"({file_hash}[^"]{1,2000})"""",
	  """msg=({additional_info}[^=]{1,2000})\s\w+=""",
     ]
  

}
```
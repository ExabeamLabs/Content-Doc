#### Parser Content
```Java
{
Name = zimperium-mobile-endpoint-security-alert
  Vendor = Zimperium
  Product = MOBILE ENDPOINT SECURITY
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "dd mm yyyy HH:mm:ss z"
  Conditions = [ """"zapp_instance_id":""",""""threat_type":""",""""threat_uuid":""",""""device_info":""" ]
  Fields = [
    """eventtimestamp":\s"({time}\d\d\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d\s\w{1,3})"""
	"""user_email":\s"({user_email}[^@"]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})"""
	"""employee_name":\s"({user_fullname}[^"\}]{1,2000})"""
	"""device_ip":\s"({src_ip}[a-fA-F\d:\.]{1,2000})"""
	"""severity":\s({alert_severity}\d{1,5})"""
	"""event_id":\s"({alert_id}[^"]{1,2000})"""
	"""story":\s"({additional_info}[^",]{1,2000})"""
	"""threat_type":\s"({alert_type}[^",]{1,200})"""
	"""Threat.+?"name":\s"({alert_name}[^"]{1,2000})"""
  ]


}
```
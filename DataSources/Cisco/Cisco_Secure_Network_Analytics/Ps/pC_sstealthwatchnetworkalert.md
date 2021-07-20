#### Parser Content
```Java
{
Name = s-stealthwatch-network-alert
  Vendor = Cisco
  Product = Cisco Secure Network Analytics
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """ stealth-smc StealthWatch[""", """protocol="""" ]
  Fields = [
    """alarm_time="({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\w)""",
    """id="({alert_id}[^"]{1,2000})"""",
    """sig="({alert_type}[^"]{1,2000})"""",
    """sev="({alert_severity}[^"]{1,2000})"""",
    """details="({additional_info}[^"]{1,2000})"""",
    """src="({src_ip}[a-fA-F\d.:]{1,2000})""",
    """src_name="({src_host}[^"]{1,2000})"""",
    """dest="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """dest_name="({dest_host}[^"]{1,2000})"""",
    """dest_user="({user}[^"]{1,2000})"""",
    """src_user="({user}[^"]{1,2000})"""",
    """dest_user="({account}[^"]{1,2000})"""",
    """protocol="({protocol}[^"]{1,2000})"""",
    """dvc_ip="({host}[a-fA-F\d.:]{1,2000})""",
    """dvc="({host}[^"]{1,2000})"""",
    """domain="({domain}[^"]{1,2000})"""",
    """port="({dest_port}[^"]{1,2000})"""", 
  ]
  DupFields = [ "alert_type->alert_name" ]
}
```
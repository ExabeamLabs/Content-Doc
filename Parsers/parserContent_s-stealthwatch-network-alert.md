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
    """id="({alert_id}[^"]+)"""",
    """sig="({alert_type}[^"]+)"""",
    """sev="({alert_severity}[^"]+)"""",
    """details="({additional_info}[^"]+)"""",
    """src="({src_ip}[a-fA-F\d.:]+)""",
    """src_name="({src_host}[^"]+)"""",
    """dest="({dest_ip}[a-fA-F\d.:]+)""",
    """dest_name="({dest_host}[^"]+)"""",
    """dest_user="({user}[^"]+)"""",
    """src_user="({user}[^"]+)"""",
    """dest_user="({account}[^"]+)"""",
    """protocol="({protocol}[^"]+)"""",
    """dvc_ip="({host}[a-fA-F\d.:]+)""",
    """dvc="({host}[^"]+)"""",
    """domain="({domain}[^"]+)"""",
    """port="({dest_port}[^"]+)"""", 
  ]
  DupFields = [ "alert_type->alert_name" ]
}
```
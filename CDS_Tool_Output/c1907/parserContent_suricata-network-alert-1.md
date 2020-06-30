#### Parser Content
```Java
{
Name = suricata-network-alert-1
  Vendor = Suricata
  Product = Suricata
  Lms = Syslog
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""pdsuricata""","""suricata""","""event_type""" ]
  Fields = [
    """"+timestamp"+:\s*"+({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
	"""exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
	""""+event_type"+:\s*"+({alert_type}[^"]+)"+""",
	""""+src_ip"+:\s*"+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"+""",
	""""+src_port"+:\s*({src_port}[^,]+)""",
	""""+dest_ip"+:\s*"+({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"+""",
	""""+dest_port"+:\s*({dest_port}[^,]+)""",
	""""+proto"+:\s*"+({protocol}[^"]+)"+""",
	""""+app_proto"+:\s*"+({app_protocol}[^"]+)"+""",
	""""+bytes_toserver"+:\s*({bytes_in}[^,]+)""",
	""""+bytes_toclient"+:\s*({bytes_out}[^,]+)""",
	""""+state"+:\s*"+({outcome}[^"]+)"+""",
	""""+reason"+:\s*"+({failure_reason}[^"]+)"+""",
        """"+http_user_agent"+:\s*"+({user_agent}[^"]+)"+""",
        """"+http_method"+:\s*"+({method}[^"]+)"+""",
        """"+filename"+:\s*"+({file_name}[^"]+)"+""",
        """"+status"+:\s*({event_code}[^,]+)""",
        """"+url"+:\s*"+({uri_path}[^"]+)"+""",
        """"+hostname"+:\s*"+({host}[^"]+)"+""",
        """"+http_content_type"+:\s*"+({mime}[^"]+)"+""",
        """\s({alert_name}suricata)"""
 ]
}
```
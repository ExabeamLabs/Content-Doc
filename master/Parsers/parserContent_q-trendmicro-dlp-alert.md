#### Parser Content
```Java
{
Name = q-trendmicro-dlp-alert
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ "Digital asset transmission detected" ," Template:" ]
  Fields = [
        """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
	"""Date\/Time:\s*({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d)""",
	"""Endpoint:\s*({src_host}[^\s]+)""",
        """User:\s*({user}.+?)\s+\w+:""",
        """Domain:\s*({domain}[^\\]+)\\""",
        """Channel:\s*({alert_type}.+?)\s+\w+:""",
        """Channel:\s*({protocol}.+?)\s+\w+:""",
        """Rule:\s*({alert_name}.+?)\s*$"""
       ]
}
```
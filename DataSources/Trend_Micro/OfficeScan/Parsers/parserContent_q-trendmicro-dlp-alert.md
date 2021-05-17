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
        """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
	"""Date\/Time:\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",
	"""Endpoint:\s{0,100}({src_host}[^\s]{1,2000})""",
        """User:\s{0,100}({user}.+?)\s{1,100}\w+:""",
        """Domain:\s{0,100}({domain}[^\\]{1,2000})\\""",
        """Channel:\s{0,100}({alert_type}.+?)\s{1,100}\w+:""",
        """Channel:\s{0,100}({protocol}.+?)\s{1,100}\w+:""",
        """Rule:\s{0,100}({alert_name}.+?)\s{0,100}$"""
       ]
}
```
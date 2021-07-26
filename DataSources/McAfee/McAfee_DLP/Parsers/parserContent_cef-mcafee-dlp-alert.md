#### Parser Content
```Java
{
Name = cef-mcafee-dlp-alert
    Vendor = McAfee
    Product = McAfee DLP
    Lms = Direct
    DataType = "dlp-alert"
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|Host Data Loss Prevention|""", """|DEVICE_PLUG|""", """Block,""" ]
    Fields = [ 
	"""\srt=({time}\d{1,100})""",
	"""exabeam_host=({host}[^\s]{1,2000})""",
	"""\sdhost=({src_host}.+?)\s\w+=""",
	"""\sdst=({src_ip}.+?)\s\w+=""",
	"""\sduser=(({domain}[^\\]{1,2000})\\+)?({user}[^=]{1,2000})\s\w+=""",
	"""\sact=({alert_type}.+?)\s\w+=""",
	"""\scs1=({alert_name}.+?)(,|\s\w+=)""",
	"""\scs4=([^,]{0,2000}
```
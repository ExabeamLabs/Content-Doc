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
	"""exabeam_host=({host}[^\s]+)""",
	"""\sdhost=({src_host}.+?)\s\w+=""",
	"""\sdst=({src_ip}.+?)\s\w+=""",
	"""\sduser=(({domain}[^\\]+)\\+)?({user}[^=]+)\s\w+=""",
	"""\sact=({alert_type}.+?)\s\w+=""",
	"""\scs1=({alert_name}.+?)(,|\s\w+=)""",
	"""\scs4=([^,]*,){4}\s{0,100}({device_id}.+?)(\s\w+=|&\d|,)""",
	"""\scs4=([^,]*,)\s{0,100}({device_type}[^,]+)""",
	"""\|McAfee\|Host Data Loss Prevention\|([^|]*\|){2}({additional_info}[^|]+)"""
    ]
  }
```
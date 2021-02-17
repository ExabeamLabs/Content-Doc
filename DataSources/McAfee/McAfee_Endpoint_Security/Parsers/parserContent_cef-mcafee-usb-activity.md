#### Parser Content
```Java
{
Name = cef-mcafee-usb-activity
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Direct
    DataType = "usb-activity"
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|Host Data Loss Prevention|""", """|DEVICE_PLUG|""" ]
    Fields = [
	"""\srt=({time}\d+)""",
	"""exabeam_host=({host}[^\s]+)""",
	"""\sdhost=({dest_host}.+?)\s\w+=""",
	"""\sdst=({dest_ip}.+?)\s\w+=""",
	"""\sduser=(({domain}[^\\]+)\\+)?({user}[^=]+)\s\w+=""",
	"""\scs4=([^,]*,){4}\s*({device_id}.+?)(\s\w+=|&\d|,)""",
	"""\scs4=([^,]*,)\s*({device_type}[^,]+)""",
	"""\scs4=([^,]*,\s*){2}({activity_details}[^,]+)""",
	"""\|McAfee\|Host Data Loss Prevention\|([^|]*\|)({activity}[^|]+)""",
    ]
  }
```
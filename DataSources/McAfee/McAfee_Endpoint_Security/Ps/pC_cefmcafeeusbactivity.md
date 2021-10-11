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
	"""\srt=({time}\d{1,100})""",
	"""exabeam_host=({host}[^\s]{1,2000})""",
	"""\sdhost=({dest_host}.+?)\s\w+=""",
	"""\sdst=({dest_ip}.+?)\s\w+=""",
	"""\sduser=(({domain}[^\\]{1,2000})\\+)?({user}[^=]{1,2000})\s\w+=""",
	"""\scs4=([^,]{0,2000},){4}\s{0,100}({device_id}.+?)(\s\w+=|&\d|,)""",
	"""\scs4=([^,]{0,2000},)\s{0,100}({device_type}[^,]{1,2000})""",
	"""\scs4=([^,]{0,2000},\s{0,100}){2}({activity_details}[^,]{1,2000})""",
	"""\|McAfee\|Host Data Loss Prevention\|([^|]{0,2000}\|)({activity}[^|]{1,2000})""",
    ]
  }
```
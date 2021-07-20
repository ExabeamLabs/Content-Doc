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
	"""\scs4=([^,]{0,2000}
```
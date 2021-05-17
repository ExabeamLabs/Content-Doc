#### Parser Content
```Java
{
Name = mcafee-usb-write
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = QRadar
    DataType = "usb-activity"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """ApplicationSet_DisplayName""", """OUTGOING_FS_REMOVABLE""", "Monitor" ]
    Fields = [
	"""UTCTime:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
	"""exabeam_host=({host}[^\s]{1,2000})""",
	"""ComputerName(=|:)\s{0,100}"({dest_host}[^"]{1,2000})"""",
	"""(\s|,)Evidence(=|:)\s{0,100}"({file_path}[^,]{1,2000})""",
	"""(\s|,)Evidence(=|:)\s{0,100}"[^",]{1,2000}\\({file_name}[^,\\]{1,2000}),""",
	"""ProcessInfo_FileName(=|:)\s{0,100}"({process_name}[^"]{1,2000})""",
	"""EventType_LocalizationKey(=|:)\s{0,100}"({activity}[^"]{1,2000})"""",
	"""TotalContentSize(=|:)\s{0,100}"({bytes}[^"]{1,2000})"""",
	"""UserName(=|:)\s{0,100}"(({domain}[^\\]{1,2000})\\)?({user}[^"]{1,2000})"""",
	"""ReactionSet_DisplayName(=|:)\s{0,100}"({action}[^"]{1,2000})"""",
	"""EventTypeDisplayName(=|:)\s{0,100}"({activity_details}[^"]{1,2000})"""",
    ]
  }
```
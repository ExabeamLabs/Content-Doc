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
	"""exabeam_host=({host}[^\s]+)""",
	"""ComputerName(=|:)\s{0,100}"({dest_host}[^"]+)"""",
	"""(\s|,)Evidence(=|:)\s{0,100}"({file_path}[^,]+)""",
	"""(\s|,)Evidence(=|:)\s{0,100}"[^",]+\\({file_name}[^,\\]+),""",
	"""ProcessInfo_FileName(=|:)\s{0,100}"({process_name}[^"]+)""",
	"""EventType_LocalizationKey(=|:)\s{0,100}"({activity}[^"]+)"""",
	"""TotalContentSize(=|:)\s{0,100}"({bytes}[^"]+)"""",
	"""UserName(=|:)\s{0,100}"(({domain}[^\\]+)\\)?({user}[^"]+)"""",
	"""ReactionSet_DisplayName(=|:)\s{0,100}"({action}[^"]+)"""",
	"""EventTypeDisplayName(=|:)\s{0,100}"({activity_details}[^"]+)"""",
    ]
  }
```
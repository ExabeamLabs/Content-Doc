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
	"""UTCTime:\s*"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
	"""exabeam_host=({host}[^\s]+)""",
	"""ComputerName(=|:)\s*"({dest_host}[^"]+)"""",
	"""(\s|,)Evidence(=|:)\s*"({file_path}[^,]+)""",
	"""(\s|,)Evidence(=|:)\s*"[^",]+\\({file_name}[^,\\]+),""",
	"""ProcessInfo_FileName(=|:)\s*"({process_name}[^"]+)""",
	"""EventType_LocalizationKey(=|:)\s*"({activity}[^"]+)"""",
	"""TotalContentSize(=|:)\s*"({bytes}[^"]+)"""",
	"""UserName(=|:)\s*"(({domain}[^\\]+)\\)?({user}[^"]+)"""",
	"""ReactionSet_DisplayName(=|:)\s*"({action}[^"]+)"""",
	"""EventTypeDisplayName(=|:)\s*"({activity_details}[^"]+)"""",
    ]
  }
```
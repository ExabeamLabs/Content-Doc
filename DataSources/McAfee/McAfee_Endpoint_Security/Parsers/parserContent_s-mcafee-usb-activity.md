#### Parser Content
```Java
{
Name = s-mcafee-usb-activity
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = Splunk
    DataType = "usb-activity"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """DEVICE_PLUG""" , """EventType_LocalizationKey"""]
    Fields = [
	"""exabeam_raw=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
	"""({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s*UTC""",
        """UTCTime:\s*"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
	"""exabeam_host=({host}[^\s]+)""",
	"""ComputerName(=|:)\s*"({dest_host}[^"]+)"""",
	"""Evidence(=|:)\s*"([^,]*,){4}\s*({device_id}.+?)(\"|&\d|,)""",
	"""Evidence(=|:)\s*"([^,]*,)\s*({device_type}[^,]+)""",
	"""EventType_LocalizationKey(=|:)\s*"({activity}[^"]+)"""",
	"""UserName(=|:)\s*"(({domain}[^\\]+)\\)?({user}[^"]+)"""",
	"""FocusDisplay(=|:)\s*"({activity_details}[^"]+)"""",
    ]
  }
```
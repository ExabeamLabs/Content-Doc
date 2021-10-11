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
	"""({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{0,100}UTC""",
        """UTCTime:\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
	"""exabeam_host=({host}[^\s]{1,2000})""",
	"""ComputerName(=|:)\s{0,100}"({dest_host}[^"]{1,2000})"""",
	"""Evidence(=|:)\s{0,100}"([^,]{0,2000},){4}\s{0,100}({device_id}.+?)(\"|&\d|,)""",
	"""Evidence(=|:)\s{0,100}"([^,]{0,2000},)\s{0,100}({device_type}[^,]{1,2000})""",
	"""EventType_LocalizationKey(=|:)\s{0,100}"({activity}[^"]{1,2000})"""",
	"""UserName(=|:)\s{0,100}"(({domain}[^\\]{1,2000})\\)?({user}[^"]{1,2000})"""",
	"""FocusDisplay(=|:)\s{0,100}"({activity_details}[^"]{1,2000})"""",
    ]
  }
```
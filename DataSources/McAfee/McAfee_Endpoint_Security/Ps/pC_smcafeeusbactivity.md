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
	"""Evidence(=|:)\s{0,100}"([^,]{0,2000}
```
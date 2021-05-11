#### Parser Content
```Java
{
Name = s-mcafee-dlp-alert
    Vendor = McAfee
    Product = McAfee DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """Block""", """DEVICE_""" , """EventType_LocalizationKey""", """PLUG"""]
    Fields = [ 
        """LocalTime="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)"""   
	"""exabeam_raw=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
	"""UTCTime(=|:)\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
	"""exabeam_host=({host}[^\s]+)""",
	"""ComputerName(=|:)\s{0,100}"({src_host}[^"]+)"""",
	"""UserName(=|:)\s{0,100}"(({domain}[^\\]+)\\)?({user}[^"]+)"""",
	"""ReactionSet_DisplayName(=|:)\s{0,100}"([^"\?]+\?)?({alert_type}\w+)""",
	"""Policy_Name(=|:)\s{0,100}"({alert_name}[^"]+)"""",
	"""Evidence(=|:)\s{0,100}"([^,]*,){4}\s{0,100}({device_id}.+?)(\"|&\d|,)""",
	"""Evidence(=|:)\s{0,100}"([^,]*,)\s{0,100}({device_type}[^,]+)""",
	"""EventTypeDisplayName(=|:)\s{0,100}"({additional_info}[^"]+)""""
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_type->dlpActionTaken", "src_host->dlpDeviceName"]
      NameTemplate = """McAfee DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```
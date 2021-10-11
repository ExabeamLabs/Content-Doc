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
	"""exabeam_host=({host}[^\s]{1,2000})""",
	"""ComputerName(=|:)\s{0,100}"({src_host}[^"]{1,2000})"""",
	"""UserName(=|:)\s{0,100}"(({domain}[^\\]{1,2000})\\)?({user}[^"]{1,2000})"""",
	"""ReactionSet_DisplayName(=|:)\s{0,100}"([^"\?]{1,2000}\?)?({alert_type}\w+)""",
	"""Policy_Name(=|:)\s{0,100}"({alert_name}[^"]{1,2000})"""",
	"""Evidence(=|:)\s{0,100}"([^,]{0,2000},){4}\s{0,100}({device_id}.+?)(\"|&\d|,)""",
	"""Evidence(=|:)\s{0,100}"([^,]{0,2000},)\s{0,100}({device_type}[^,]{1,2000})""",
	"""EventTypeDisplayName(=|:)\s{0,100}"({additional_info}[^"]{1,2000})""""
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_type->dlpActionTaken", "src_host->dlpDeviceName"]
      NameTemplate = """McAfee DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```
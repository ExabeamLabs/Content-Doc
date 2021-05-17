#### Parser Content
```Java
{
Name = microsoft-scep-security-alert
  Vendor = Microsoft
  Product = Windows Defender
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """Name=MalwareInfection""", """RemediationPendingAction=""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """exabeam_time=({time}[^,=]{1,2000}?)exabeam_""",
    """TargetHost=({dest_host}[^,=]{1,2000}?),""",
    """TargetUser=({domain}[^,=]{1,2000}?)\\+({user}[^,=\\]{1,2000}?),""",
    """TargetProcess=({process}({directory}[^,=]{1,2000}?\\+)({process_name}[^\\,=]{0,2000}?)),""",
    """TargetResource=({malware_url}[^=,]{1,2000}?),""",
    """ClassificationType=({alert_name}[^,=]{1,2000}),""",
    """ClassificationSeverity=({alert_severity}[^,=]{1,2000}),""",
    """ClassificationCategory=({alert_type}[^,=]{1,2000}),""",
  ]
  DupFields = ["directory->process_directory"]
}
```
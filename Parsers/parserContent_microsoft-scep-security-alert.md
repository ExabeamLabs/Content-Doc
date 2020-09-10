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
    """exabeam_host=({host}[\w\-.]+)""",
    """exabeam_time=({time}[^,=]+?)exabeam_""",
    """TargetHost=({dest_host}[^,=]+?),""",
    """TargetUser=({domain}[^,=]+?)\\+({user}[^,=\\]+?),""",
    """TargetProcess=({process}({directory}[^,=]+?\\+)({process_name}[^\\,=]*?)),""",
    """TargetResource=({malware_url}[^=,]+?),""",
    """ClassificationType=({alert_name}[^,=]+),""",
    """ClassificationSeverity=({alert_severity}[^,=]+),""",
    """ClassificationCategory=({alert_type}[^,=]+),""",
  ]
  DupFields = ["directory->process_directory"]
}
```
#### Parser Content
```Java
{
Name = cef-carbonblack-process-created
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "process-created"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """threatIndicators":""", """processDetails":""", """fileType=process"""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """eventTime=({time}\d{1,100})""",
    """deviceIpAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """deviceName=(({domain}[^\\\s]+)\\+)?({src_host}[^\\\s]+)""",
    """email=(({domain}[^\\\s"]+)\\+)?({user}\w+)""",
    """eventType=({alert_name}.+?)\s\w+=""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]+)""",
    """applicationPath=({process}(({directory}[^"=,]+)\\)?({process_name}[^\s\\]+))\s\w+=""",
    """applicationName=({process_name}.+?)\s\w+=""",
    """targetPriorityType=({alert_severity}.+?)\s\w+=""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```
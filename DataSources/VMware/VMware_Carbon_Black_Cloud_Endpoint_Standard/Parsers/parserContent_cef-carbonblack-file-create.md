#### Parser Content
```Java
{
Name = cef-carbonblack-file-create
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "file-write"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """threatIndicators":""", """fileType=file"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """eventTime=({time}\d+)""",
    """"deviceIpAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """deviceName=(({domain}[^\\\s"]+)\\+)?({src_host}[^\\\s"]+)""",
    """email=(({domain}[^\\\s"]+)\\+)?({user}\w+)""",
    """eventType=({alert_name}.+?)\s\w+=""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]+)""",
    """applicationPath=({process}(({directory}[^"=,]+)\\)?({process_name}[^\s\\]+))\s\w+=""",
    """applicationName=({process_name}.+?)\s\w+=""",
    """targetPriorityType=({alert_severity}.+?)\s\w+=""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """fname=({file_path}(\w:|\\\\).+?)\s+""",
    """fname=({file_parent}(\w:|\\\\).+?)\\+(?:[^\\=]+?)\s+""",
    """fname=({file_path}(({file_parent}\w+:[^"].+?)\\+)?({file_name}[^"\\,:]+))\s+\w+="""
    """fname=(|([^\/,]+?(\.({file_ext}[^\/,\.]+?))?))\s+(\w+=|$)""",
    """>({file_name}[^<"']+)<\/link><\/share>"*\s*was created by the application"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```
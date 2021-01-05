#### Parser Content
```Java
{
Name = cef-carbonblack-process-created-3
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "process-created"
  TimeFormat = """epoch"""
  Conditions = [  """CEF:""", """threatIndicators""", """|security-threat-detected""", """act=run""", """invoked""", """parentPrivatePid":""""]
  Fields = [
    """exabeam_host=({host}[\w\-\.]+)""",
    """eventTime=({time}\d+)""",
    """deviceIpAddress=({src_ip}[A-Fa-f:\d\.]+)""",
    """src=({src_ip}[A-Fa-f:\d\.]+)""",
    """deviceName=(({domain}[^\\]+)\\+)?({src_host}[^=]+?)\s+\w+=""",
    """email=(({domain}[^\\\s"]+)\\+)?(HiveStreamingService|SYSTEM|({user}[^@=]+))\s+\w+=""",
    """suser=(({domain}[^\\\/=]+)[\\\/]+)?(HiveStreamingService|SYSTEM|({user}[^=\s]+?))(\s+\w+=|\s*$)""",
    """flexString1=({alert_name}[^=]+?)\s+\w+=""",
    """eventType=({alert_name}[^=]+?)\s+\w+=""",
    """applicationName=({process_name}[^\s]+)\s+\w+=""",
    """targetPriorityType=({alert_severity}[^=]+?)\s+\w+=""",
    """\Wmsg=({additional_info}[^=]+?)\s+(\w+=|$)""",
    """applicationPath=({process}(({directory}[^"=,]+)\\)?({process_name}[^\s\\]+))\s+\w+=""",
    """fname=\s*({file_path}(\w:|\\\\)[^\s]+)\s+""",
    """fname=\s*({file_name}[^\\\/"=]+?)\s+(\w+=|$)""",
    """fname=\s*({file_parent}(\w:|\\\\).+?)\\+(?:[^\\=]+?)\s+""",
    """fname=\s*(|([^\/,]+?(\.({file_ext}[^\/,\.]+?))?))\s+(\w+=|$)""",
    """act=({accesses}[^=]+?)\s+(\w+=|$)""",
    """"targetApp":\{[^}]+"sha256Hash":"({sha256}[^"]+)"""",
    """"targetApp":\{[^}]+"md5Hash":"({md5}[^"]+)"""",
  ]
  DupFields = ["directory->process_directory", "alert_name->alert_type"]
}
```
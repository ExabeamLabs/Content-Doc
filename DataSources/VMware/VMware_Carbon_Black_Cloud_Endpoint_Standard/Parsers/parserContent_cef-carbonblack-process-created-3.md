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
    """eventTime=({time}\d{1,100})""",
    """deviceIpAddress=({src_ip}[A-Fa-f:\d\.]+)""",
    """src=({src_ip}[A-Fa-f:\d\.]+)""",
    """deviceName=(({domain}[^\\]+)\\+)?({src_host}[^=]+?)\s{1,100}\w+=""",
    """email=(({domain}[^\\\s"]+)\\+)?(HiveStreamingService|SYSTEM|({user}[^@=]+))\s{1,100}\w+=""",
    """suser=(({domain}[^\\\/=]+)[\\\/]+)?(HiveStreamingService|SYSTEM|({user}[^=\s]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """flexString1=({alert_name}[^=]+?)\s{1,100}\w+=""",
    """eventType=({alert_name}[^=]+?)\s{1,100}\w+=""",
    """applicationName=({process_name}[^\s]+)\s{1,100}\w+=""",
    """targetPriorityType=({alert_severity}[^=]+?)\s{1,100}\w+=""",
    """\Wmsg=({additional_info}[^=]+?)\s{1,100}(\w+=|$)""",
    """applicationPath=({process}(({directory}[^"=,]+)\\)?({process_name}[^\s\\]+))\s{1,100}\w+=""",
    """fname=\s{0,100}({file_path}(\w:|\\\\)[^\s]+)\s{1,100}""",
    """fname=\s{0,100}({file_name}[^\\\/"=]+?)\s{1,100}(\w+=|$)""",
    """fname=\s{0,100}({file_parent}(\w:|\\\\).+?)\\+(?:[^\\=]+?)\s{1,100}""",
    """fname=\s{0,100}(|([^\/,]+?(\.({file_ext}[^\/,\.]+?))?))\s{1,100}(\w+=|$)""",
    """act=({accesses}[^=]+?)\s{1,100}(\w+=|$)""",
    """"targetApp":\{[^}]+"sha256Hash":"({sha256}[^"]+)"""",
    """"targetApp":\{[^}]+"md5Hash":"({md5}[^"]+)"""",
  ]
  DupFields = ["directory->process_directory", "alert_name->alert_type"]
}
```
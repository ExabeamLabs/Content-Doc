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
    """exabeam_host=({host}[\w\-\.]{1,2000})""",
    """eventTime=({time}\d{1,100})""",
    """deviceIpAddress=({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d\.]{1,2000})""",
    """deviceName=(({domain}[^\\]{1,2000})\\+)?({src_host}[^=]{1,2000}?)\s{1,100}\w+=""",
    """email=(({domain}[^\\\s"]{1,2000})\\+)?(HiveStreamingService|SYSTEM|({user}[^@=]{1,2000}))\s{1,100}\w+=""",
    """suser=(({domain}[^\\\/=]{1,2000})[\\\/]{1,2000})?(HiveStreamingService|SYSTEM|({user}[^=\s]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """flexString1=({alert_name}[^=]{1,2000}?)\s{1,100}\w+=""",
    """eventType=({alert_name}[^=]{1,2000}?)\s{1,100}\w+=""",
    """applicationName=({process_name}[^\s]{1,2000})\s{1,100}\w+=""",
    """targetPriorityType=({alert_severity}[^=]{1,2000}?)\s{1,100}\w+=""",
    """\Wmsg=({additional_info}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """applicationPath=({process}(({directory}[^"=,]{1,2000})\\)?({process_name}[^\s\\]{1,2000}))\s{1,100}\w+=""",
    """fname=\s{0,100}({file_path}(\w:|\\\\)[^\s]{1,2000})\s{1,100}""",
    """fname=\s{0,100}({file_name}[^\\\/"=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """fname=\s{0,100}({file_parent}(\w:|\\\\).+?)\\+(?:[^\\=]{1,2000}?)\s{1,100}""",
    """fname=\s{0,100}(|([^\/,]{1,2000}?(\.({file_ext}[^\/,\.]{1,2000}?))?))\s{1,100}(\w+=|$)""",
    """act=({accesses}[^=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """"targetApp":\{[^}]{1,2000}"sha256Hash":"({sha256}[^"]{1,2000})"""",
    """"targetApp":\{[^}]{1,2000}"md5Hash":"({md5}[^"]{1,2000})"""",
  ]
  DupFields = ["directory->process_directory", "alert_name->alert_type"]
}
```
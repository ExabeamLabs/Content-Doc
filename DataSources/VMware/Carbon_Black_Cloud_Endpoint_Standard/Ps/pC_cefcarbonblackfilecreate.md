#### Parser Content
```Java
{
Name = cef-carbonblack-file-create
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "file-write"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """threatIndicators":""", """fileType=file"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """eventTime=({time}\d{1,100})""",
    """"deviceIpAddress=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """deviceName =(({domain}[^\\\s"]{1,2000})\\+)?({src_host}[^\\\s"]{1,2000})""",
    """email=(({domain}[^\\\s"]{1,2000})\\+)?({user}\w+)""",
    """eventType=({alert_name}.+?)\s\w+=""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]{1,2000})""",
    """applicationPath=({process}(({directory}[^"=,]{1,2000})\\)?({process_name}[^\s\\]{1,2000}))\s\w+=""",
    """applicationName =({process_name}.+?)\s\w+=""",
    """targetPriorityType=({alert_severity}.+?)\s\w+=""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """fname=({file_path}(\w:|\\\\).+?)\s{1,100}""",
    """fname=({file_parent}(\w:|\\\\).+?)\\+(?:[^\\=]{1,2000}?)\s{1,100}""",
    """fname=({file_path}(({file_parent}\w+:[^"].+?)\\+)?({file_name}[^"\\,:]{1,2000}))\s{1,100}\w+="""
    """fname=(|([^\/,]{1,2000}?(\.({file_ext}[^\/,\.]{1,2000}?))?))\s{1,100}(\w+=|$)""",
    """>({file_name}[^<"']{1,2000})<\/link><\/share>"{0,20}\s{0,100}was created by the application"""
  ]
  DupFields = [ "directory->process_directory" ]


}
```
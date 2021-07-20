#### Parser Content
```Java
{
Name = cef-carbonblack-security-alert-1
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """threatIndicators""" , """|security-threat-detected""", """targetPriorityType=HIGH""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """eventTime=({time}\d{1,100})""",
    """deviceIpAddress=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """deviceName=(({domain}[^\\\s"]{1,2000})\\+)?({src_host}[^\\\s"]{1,2000})"?""",
    """email=(({domain}[^\\\s"]{1,2000})\\+)?(SYSTEM|({user}[^\s"@]{1,2000}))"""",
    """\Wsuser=(({domain}[^\\\/=]{1,2000})[\\\/]{1,2000})?(SYSTEM|({user}[^=\s"@]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """flexString1=({alert_name}.+?)\s\w+=""",
    """eventType=({alert_name}.+?)\s\w+="?""",
    """applicationName=({process_name}.+?)\s\w+="""",
    """targetPriorityType=({alert_severity}.+?)\s\w+="?""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """flexString1=({alert_type}[^\s]{1,2000})""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]{1,2000})""",
    """applicationPath=({process}(({directory}[^"=,]{1,2000})\\)?({process_name}[^\s\\]{1,2000}))\s\w+=""",
    """dhost=({web_domain}[^\s]{1,2000}\.[^\s]{1,2000})"""
    """dhost=[^"\s]{0,2000}?({top_domain}[^\/\.\s]{1,2000}(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """dst=({dest_ip}[^\s]{1,2000})""",
    """fname=({file_path}(\w:|\\\\).+?)\s{1,100}""",
    """fname=({file_parent}(\w:|\\\\).+?)\\+(?:[^\\=]{1,2000}?)\s{1,100}""",
    """fname=({file_path}(({file_parent}\w+:[^"].+?)\\+)?({file_name}[^"\\,:]{1,2000}))\s{1,100}\w+="""
    """fname=(|([^\/,]{1,2000}?(\.({file_ext}[^\/,\.]{1,2000}?))?))\s{1,100}(\w+=|$)""",
    """>({file_name}[^<"']{1,2000})<\/link><\/share>"{0,20}\s{0,100}was created by the application"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```
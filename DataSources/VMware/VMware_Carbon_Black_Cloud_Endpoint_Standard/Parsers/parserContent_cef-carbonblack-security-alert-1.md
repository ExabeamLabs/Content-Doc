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
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """eventTime=({time}\d{1,100})""",
    """deviceIpAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """deviceName=(({domain}[^\\\s"]+)\\+)?({src_host}[^\\\s"]+)"?""",
    """email=(({domain}[^\\\s"]+)\\+)?(SYSTEM|({user}[^\s"@]+))"""",
    """\Wsuser=(({domain}[^\\\/=]+)[\\\/]+)?(SYSTEM|({user}[^=\s"@]+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """flexString1=({alert_name}.+?)\s\w+=""",
    """eventType=({alert_name}.+?)\s\w+="?""",
    """applicationName=({process_name}.+?)\s\w+="""",
    """targetPriorityType=({alert_severity}.+?)\s\w+="?""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
    """flexString1=({alert_type}[^\s]+)""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]+)""",
    """applicationPath=({process}(({directory}[^"=,]+)\\)?({process_name}[^\s\\]+))\s\w+=""",
    """dhost=({web_domain}[^\s]+\.[^\s]+)"""
    """dhost=[^"\s]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """dst=({dest_ip}[^\s]+)""",
    """fname=({file_path}(\w:|\\\\).+?)\s{1,100}""",
    """fname=({file_parent}(\w:|\\\\).+?)\\+(?:[^\\=]+?)\s{1,100}""",
    """fname=({file_path}(({file_parent}\w+:[^"].+?)\\+)?({file_name}[^"\\,:]+))\s{1,100}\w+="""
    """fname=(|([^\/,]+?(\.({file_ext}[^\/,\.]+?))?))\s{1,100}(\w+=|$)""",
    """>({file_name}[^<"']+)<\/link><\/share>"{0,20}\s{0,100}was created by the application"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```
#### Parser Content
```Java
{
Name = cef-carbonblack-security-alert-1
  Vendor = Carbon Black
  Product = Cb Defense
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """threatIndicators":""" , """|security-threat-detected"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """eventTime=({time}\d+)""",
    """deviceIpAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """deviceName=(({domain}[^\\\s"]+)\\+)?({src_host}[^\\\s"]+)"?""",
    """email=(({domain}[^\\\s"]+)\\+)?({user}\w+)"""",
    """\Wsuser=(({domain}[^\\\/=]+)[\\\/]+)?({user}[^=]+?)(\s+\w+=|\s*$)""",
    """flexString1=({alert_name}.+?)\s\w+=""",
    """eventType=({alert_name}.+?)\s\w+="?""",
    """applicationName=({process_name}.+?)\s\w+="""",
    """targetPriorityType=({alert_severity}.+?)\s\w+="?""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
    """flexString1=({alert_type}[^\s]+)""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]+)""",
    """applicationPath=({process}(({directory}[^"=,]+)\\)?({process_name}[^\s\\]+))\s\w+=""",
    """dhost=({web_domain}[^\s]+\.[^\s]+)"""
    """dhost=[^"\s]*?({top_domain}[^\/\.\s]+(?i)(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)""",
    """dst=({dest_ip}[^\s]+)""",
    """fname=({file_path}(\w:|\\\\).+?)\s+""",
    """fname=({file_parent}(\w:|\\\\).+?)\\+(?:[^\\=]+?)\s+""",
    """fname=({file_path}(({file_parent}\w+:[^"].+?)\\+)?({file_name}[^"\\,:]+))\s+\w+="""
    """fname=(|([^\/,]+?(\.({file_ext}[^\/,\.]+?))?))\s+(\w+=|$)""",
    """>({file_name}[^<"']+)<\/link><\/share>"*\s*was created by the application"""
  ]
  DupFields = [ "directory->process_directory" ]
}
```
#### Parser Content
```Java
{
Name = cef-carbonblack-file-create
  Vendor = Carbon Black
  Product = Cb Defense
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

{
  Name = leef-cbdef-security-alert
  Vendor = Carbon Black
  Product = Cb Defense
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "MMM-dd-YYYY HH:mm:ss z"
  Conditions = [ """|CarbonBlack|CbDefense|""", """LEEF:""", """Active_Threat""" ]
  Fields = [
        """\sdevTime=({time}\w+\-\d{1,2}\-\d{4} \d\d:\d\d:\d\d \w+)""",
        """\sdeviceName=(({domain}[^\s\\]+)\\)?({src_host}[^\s\\]+)\s""",
        """\sinternalIpAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
        """\sexternalIpAddress=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
        """\ssev=({alert_severity}\d+)\s""",
        """\ssummary=({additional_info}.+?)\s+groupName=""",
        """\ssignature=({alert_type}[^\s]+)""",
        """\sincidentId=({alert_id}[^\s]+)""",
        """\sapplicationName=({process_name}.+?)\s+indicatorName=""",
        """\|CarbonBlack\|CbDefense\|(.*?)\|({alert_name}.*?)\|""",
        """\semail=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)"""        
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "dest_ip->malwareAttackerIp", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
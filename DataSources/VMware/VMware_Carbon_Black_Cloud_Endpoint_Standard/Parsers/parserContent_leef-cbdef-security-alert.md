#### Parser Content
```Java
{
Name = leef-cbdef-security-alert
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
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
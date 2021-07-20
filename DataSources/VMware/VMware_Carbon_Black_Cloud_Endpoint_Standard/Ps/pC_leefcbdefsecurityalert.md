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
        """\sdeviceName=(({domain}[^\s\\]{1,2000})\\)?({src_host}[^\s\\]{1,2000})\s""",
        """\sinternalIpAddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
        """\sexternalIpAddress=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
        """\ssev=({alert_severity}\d{1,100})\s""",
        """\ssummary=({additional_info}.+?)\s{1,100}groupName=""",
        """\ssignature=({alert_type}[^\s]{1,2000})""",
        """\sincidentId=({alert_id}[^\s]{1,2000})""",
        """\sapplicationName=({process_name}.+?)\s{1,100}indicatorName=""",
        """\|CarbonBlack\|CbDefense\|(.*?)\|({alert_name}.*?)\|""",
        """\semail=(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})"""        
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "dest_ip->malwareAttackerIp", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_host->malwareVictimHost"]
    NameTemplate = """Carbon Black Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
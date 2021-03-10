#### Parser Content
```Java
{
Name = s-crowdstrike-security-alert
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """"eventType":""", """"DetectionSummaryEvent"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"eventCreationTime":\s*({time}\d+)""",
    """"DetectName":\s*"({alert_type}[^"]+)""",
    """"DetectDescription":\s*"({alert_name}[^"]+)""",
    """"Severity":\s*({alert_severity}[^",]+)""",
    """"DetectId":\s*"({alert_id}[^"]+)""",
    """({additional_info_1}"DocumentsAccessed":\s*[^\]]+\]).*?({additional_info_2}"ExecutablesWritten":\s*[^\]]+\])""",
    """"FileName":\s*"(|({process_name}[^"]+))"""",
    """"FilePath":\s*"(|({file_path}[^"]+))"""",
    """"CommandLine":\s*"(\\")?(|({command_line}[^"]+))"""",
    """"SensorId":\s*"({sensor_id}[^"]+)""",
    """"ComputerName":\s*"({src_host}[^"]+)""",
    """"LocalIP":\s*"({src_ip}[^"]+)""", 
    """"ComputerName":\s*"({src_host}[^"]+).*?"LocalAddress":\s*"({src_ip}[^"]+)","LocalPort":\s*({src_port}\d+),"RemoteAddress":\s*"({dest_ip}[^"]+)","RemotePort":\s*({dest_port}\d+),"ConnectionDirection":\s*0""",
    """"ComputerName":\s*"({dest_host}[^"]+).*?"LocalAddress":\s*"({dest_ip}[^"]+)","LocalPort":\s*({dest_port}\d+),"RemoteAddress":\s*"({src_ip}[^"]+)","RemotePort":\s*({src_port}\d+),"ConnectionDirection":\s*1""",
    """"MD5String":\s*"(|({md5}[^"]+))"""",
    """"UserName":\s*"(|N/A|({user}[^"]+))"""",
  ]
  DupFields = [ "command_line->malware_url" ]
  SOAR {		
    IncidentType = "malware"		
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp"]		
    NameTemplate = """CrowdStrike Alert ${alert_name} found"""		
    ProjectName = "SOC"		
    EntityFields = [		
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
#### Parser Content
```Java
{
Name = json-cisco-firesight-alert-1
  Vendor = Cisco
  Product = Cisco Firepower
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"malwareEventType":""", """"detectionName":""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """eventDateTime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """malwareEventType":\s*"({alert_name}[^"]+)""",
    """malwareEventSubtype":\s*"(N\/A|({alert_type}[^"]+))""",
    """sourceIpAddress":\s*"({src_ip}[a-fA-F\d.:]+)""",
    """destinationIpAddress":\s*"(::|({dest_ip}[a-fA-F\d.:]+))""",
    """detector":\s*"({detector}[^"]+)""",
    """fileType":\s*"({file_type}[^"]+)""",
    """fileName":\s*\{[^\}]*?"data":\s*"({file_name}[^"]+)""",
    """parentFileName":\s*\{[^\}]*?"data":\s*"({process_name}[^"]+)""",
    """detectionName":\s*\{[^\}]*?"data":\s*"({alert_name}[^"]+)""",
    """filePath":\s*\{[^\}]*?"data":\s*"({file_path}[^"]+)""",
    """uri":\s*\{[^\}]*?"data":\s*"({malware_url}[^"]+)""",
    """user":\s*\{[^\}]*?"data":\s*"({user}[^"@]+)(@({domain}[^"@]+))?""",
    """parentShaHash":\s*\{[^\}]*?"data":\s*"({md5}[^"]+)""",
    """"sensor":\s*"({sensor_name}[^"]+)""",
    """"fileAction":\s*"({file_action}[^"]+)""",
    """"filePolicy":\s*"({file_policy}[^"]+)""",
    """"direction":\s*"({direction}[^"]+)""",
    """"sourcePort":\s*({src_port}\d+)""",
    """"destinationPort":\s*({dest_port}\d+)""",
    """"protocol":\s*({protocol}[^,]+)""",
    """Old Disp:\s*({old_disposition}[^,]+)""",
    """New Disp:\s*({new_disposition}[^,]+)""",
    """threatScore":\s({alert_severity}\d+)""",
  ]
  SOAR {
   IncidentType = "malware"
   DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_ip->malwareVictimHost", "dest_ip->malwareAttackerIp", "malware_url->malwareAttackerUrl", "file_name->malwareAttackerFile"]
   NameTemplate = """Cisco Sourcefire Alert ${alert_name} found"""
   ProjectName = "SOC"
   EntityFields = [
     {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
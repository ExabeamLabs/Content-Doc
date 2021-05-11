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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """eventDateTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """malwareEventType":\s{0,100}"({alert_name}[^"]+)""",
    """malwareEventSubtype":\s{0,100}"(N\/A|({alert_type}[^"]+))""",
    """sourceIpAddress":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
    """destinationIpAddress":\s{0,100}"(::|({dest_ip}[a-fA-F\d.:]+))""",
    """detector":\s{0,100}"({detector}[^"]+)""",
    """fileType":\s{0,100}"({file_type}[^"]+)""",
    """fileName":\s{0,100}\{[^\}]*?"data":\s{0,100}"({file_name}[^"]+)""",
    """parentFileName":\s{0,100}\{[^\}]*?"data":\s{0,100}"({process_name}[^"]+)""",
    """detectionName":\s{0,100}\{[^\}]*?"data":\s{0,100}"({alert_name}[^"]+)""",
    """filePath":\s{0,100}\{[^\}]*?"data":\s{0,100}"({file_path}[^"]+)""",
    """uri":\s{0,100}\{[^\}]*?"data":\s{0,100}"({malware_url}[^"]+)""",
    """user":\s{0,100}\{[^\}]*?"data":\s{0,100}"({user}[^"@]+)(@({domain}[^"@]+))?""",
    """parentShaHash":\s{0,100}\{[^\}]*?"data":\s{0,100}"({md5}[^"]+)""",
    """"sensor":\s{0,100}"({sensor_name}[^"]+)""",
    """"fileAction":\s{0,100}"({file_action}[^"]+)""",
    """"filePolicy":\s{0,100}"({file_policy}[^"]+)""",
    """"direction":\s{0,100}"({direction}[^"]+)""",
    """"sourcePort":\s{0,100}({src_port}\d{1,100})""",
    """"destinationPort":\s{0,100}({dest_port}\d{1,100})""",
    """"protocol":\s{0,100}({protocol}[^,]+)""",
    """Old Disp:\s{0,100}({old_disposition}[^,]+)""",
    """New Disp:\s{0,100}({new_disposition}[^,]+)""",
    """threatScore":\s({alert_severity}\d{1,100})""",
  ]
  SOAR {
   IncidentType = "malware"
   DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_ip->malwareVictimHost", "dest_ip->malwareAttackerIp", "malware_url->malwareAttackerUrl", "file_name->malwareAttackerFile"]
   NameTemplate = """Cisco Sourcefire Alert ${alert_name} found"""
   ProjectName = "SOC"
   EntityFields = [
     {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
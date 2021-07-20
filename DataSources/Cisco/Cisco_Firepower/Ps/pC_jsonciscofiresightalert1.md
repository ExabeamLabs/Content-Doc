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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """eventDateTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """malwareEventType":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """malwareEventSubtype":\s{0,100}"(N\/A|({alert_type}[^"]{1,2000}))""",
    """sourceIpAddress":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """destinationIpAddress":\s{0,100}"(::|({dest_ip}[a-fA-F\d.:]{1,2000}))""",
    """detector":\s{0,100}"({detector}[^"]{1,2000})""",
    """fileType":\s{0,100}"({file_type}[^"]{1,2000})""",
    """fileName":\s{0,100}\{[^\}]{0,2000}?"data":\s{0,100}"({file_name}[^"]{1,2000})""",
    """parentFileName":\s{0,100}\{[^\}]{0,2000}?"data":\s{0,100}"({process_name}[^"]{1,2000})""",
    """detectionName":\s{0,100}\{[^\}]{0,2000}?"data":\s{0,100}"({alert_name}[^"]{1,2000})""",
    """filePath":\s{0,100}\{[^\}]{0,2000}?"data":\s{0,100}"({file_path}[^"]{1,2000})""",
    """uri":\s{0,100}\{[^\}]{0,2000}?"data":\s{0,100}"({malware_url}[^"]{1,2000})""",
    """user":\s{0,100}\{[^\}]{0,2000}?"data":\s{0,100}"({user}[^"@]{1,2000})(@({domain}[^"@]{1,2000}))?""",
    """parentShaHash":\s{0,100}\{[^\}]{0,2000}?"data":\s{0,100}"({md5}[^"]{1,2000})""",
    """"sensor":\s{0,100}"({sensor_name}[^"]{1,2000})""",
    """"fileAction":\s{0,100}"({file_action}[^"]{1,2000})""",
    """"filePolicy":\s{0,100}"({file_policy}[^"]{1,2000})""",
    """"direction":\s{0,100}"({direction}[^"]{1,2000})""",
    """"sourcePort":\s{0,100}({src_port}\d{1,100})""",
    """"destinationPort":\s{0,100}({dest_port}\d{1,100})""",
    """"protocol":\s{0,100}({protocol}[^,]{1,2000})""",
    """Old Disp:\s{0,100}({old_disposition}[^,]{1,2000})""",
    """New Disp:\s{0,100}({new_disposition}[^,]{1,2000})""",
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
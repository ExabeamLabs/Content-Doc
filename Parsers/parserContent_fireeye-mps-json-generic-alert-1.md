#### Parser Content
```Java
{
Name = fireeye-mps-json-generic-alert-1
  Vendor = FireEye
  Product = FireEye Network Security (NX)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"alertType":""", """"fireeye_rule"""", """"severity":""", """"srcipv4":""" ]
  Fields = [
    """exabeam_host=({host}\S+)""",
    """"createDate.+?"id":\s*"({alert_id}[^"]+)""",
    """"risk":\s*"({alert_severity}[^"]+)""",
    """"updateDate":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"srcipv4":\s*"({src_ip}[^"]+)""",
    """"srcipv6":\s*"({src_ip}[^"]+)""",
    """"srchost":\s*"({src_host}[^"]+)""",
    """"message":\s*"({alert_name}[^"]+?)\s+\[({alert_type}[^"]+?)\]""",
    """"virus":\s*"({alert_name}[^"]+)""",
    """"devicename":\s*"({host}[^"]+)""",
    """"srcport":\s*({src_port}\d+)""",
    """"action":\s*"({outcome}[^"]+)""",
    """"dstipv4":\s*"({dest_ip}[^"]+)""",
    """"dstport":\s*({dest_port}\d+)""",
    """"detail":.+?"uri":\s*"({malware_url}[^"]+)"""",
    """"description":\s*"({additional_info}[^"]+)""",
    """"username":\s*"({user}[^"]+)""",
  ]
    SOAR {
        IncidentType = "malware"
        DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp", "malware_url->malwareAttackerUrl"]
        NameTemplate = """FireEye Alert ${alert_name} found"""
        ProjectName = "SOC"
        EntityFields = [
          {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}
```
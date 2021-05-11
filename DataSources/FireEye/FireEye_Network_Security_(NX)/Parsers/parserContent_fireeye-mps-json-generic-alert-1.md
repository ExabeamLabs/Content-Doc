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
    """"createDate.+?"id":\s{0,100}"({alert_id}[^"]+)""",
    """"risk":\s{0,100}"({alert_severity}[^"]+)""",
    """"updateDate":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"srcipv4":\s{0,100}"({src_ip}[^"]+)""",
    """"srcipv6":\s{0,100}"({src_ip}[^"]+)""",
    """"srchost":\s{0,100}"({src_host}[^"]+)""",
    """"message":\s{0,100}"({alert_name}[^"]+?)\s{1,100}\[({alert_type}[^"]+?)\]""",
    """"virus":\s{0,100}"({alert_name}[^"]+)""",
    """"devicename":\s{0,100}"({host}[^"]+)""",
    """"srcport":\s{0,100}({src_port}\d{1,100})""",
    """"action":\s{0,100}"({outcome}[^"]+)""",
    """"dstipv4":\s{0,100}"({dest_ip}[^"]+)""",
    """"dstport":\s{0,100}({dest_port}\d{1,100})""",
    """"detail":.+?"uri":\s{0,100}"({malware_url}[^"]+)"""",
    """"description":\s{0,100}"({additional_info}[^"]+)""",
    """"username":\s{0,100}"({user}[^"]+)""",
  ]
    SOAR {
        IncidentType = "malware"
        DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost", "dest_ip->malwareAttackerIp", "malware_url->malwareAttackerUrl"]
        NameTemplate = """FireEye Alert ${alert_name} found"""
        ProjectName = "SOC"
        EntityFields = [
          {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address"]}
```
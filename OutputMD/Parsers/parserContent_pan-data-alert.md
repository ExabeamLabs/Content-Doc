#### Parser Content
```Java
{
Name = pan-data-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,data,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """THREAT,({alert_type}[^,]+),[^,]*,({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d),({src_ip}[\da-fA-F\.:]+),({dest_ip}[\da-fA-F\.:]+)(,|$)""",
    """THREAT,data,([^,]*,){25}({action}[^,]+)""",
    """THREAT,data,([^,]*,){26}(("*[^"]*")|[^,]*),([^,]*,){27}({host}[\w\-\.]+)(,|$)""",
    """THREAT,data,([^,]*,){8}(|({domain}[^\\,]+))\\?(|({user}[^\\,]+))(,|$)""",
    """THREAT,data,([^,]*,){7}(|({domain}[^\\,]+))\\?(|({user}[^\\,]+))(,|$)""",
    """THREAT,data,([^,]*,){26}(("*[^"]*")|[^,]*),({alert_name}[^,]+)(,|$)""",
    """THREAT,data,([^,]*,){26}(("*[^"]*")|[^,]*),([^,]*,){4}({alert_id}\d+)(,|$)""",
    """THREAT,data,([^,]*,){26}(("*[^"]*")|[^,]*),([^,]*,){2}({alert_severity}[\w\-\.]+)(,|$)""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "dest_ip->malwareAttackerIp", "action->description"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
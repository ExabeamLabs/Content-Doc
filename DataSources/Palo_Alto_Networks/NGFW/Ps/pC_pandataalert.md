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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,({alert_type}[^,]{1,2000}),[^,]{0,2000},({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d),({src_ip}[\da-fA-F\.:]{1,2000}),({dest_ip}[\da-fA-F\.:]{1,2000})(,|$)""",
    """THREAT,data,([^,]{0,2000},){25}({action}[^,]{1,2000})""",
    """THREAT,data,([^,]{0,2000},){26}(("{0,20}[^"]{0,2000}")|[^,]{0,2000}),([^,]{0,2000},){27}({host}[\w\-\.]{1,2000})(,|$)""",
    """THREAT,data,([^,]{0,2000},){8}(|({domain}[^\\,]{1,2000}))\\?(|({user}[^\\,]{1,2000}))(,|$)""",
    """THREAT,data,([^,]{0,2000},){7}(|({domain}[^\\,]{1,2000}))\\?(|({user}[^\\,]{1,2000}))(,|$)""",
    """THREAT,data,([^,]{0,2000},){26}(("{0,20}[^"]{0,2000}")|[^,]{0,2000}),({alert_name}[^,]{1,2000})(,|$)""",
    """THREAT,data,([^,]{0,2000},){26}(("{0,20}[^"]{0,2000}")|[^,]{0,2000}),([^,]{0,2000},){4}({alert_id}\d{1,100})(,|$)""",
    """THREAT,data,([^,]{0,2000},){26}(("{0,20}[^"]{0,2000}")|[^,]{0,2000}),([^,]{0,2000},){2}({alert_severity}[\w\-\.]{1,2000})(,|$)""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "dest_ip->malwareAttackerIp", "action->description"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
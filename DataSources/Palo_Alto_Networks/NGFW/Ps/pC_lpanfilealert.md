#### Parser Content
```Java
{
Name = l-pan-file-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,THREAT,file,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """THREAT,[^,]{1,2000},[^,]{1,2000},({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z),""",
    """THREAT,file,\d{1,100},({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """THREAT,([^,]{0,2000},){3}({src_ip}[^,]{0,2000}?),({dest_ip}[^,]{0,2000}?),""",
    """THREAT,file,((""|".*?[^"]"|[^,]{0,2000}),){25}({action}[^,]{1,2000})""",
    """THREAT,file,((""|".*?[^"]"|[^,]{0,2000}),){54}({host}[\w\-\.]{1,2000})(,|$)""",
    """:\d\d:\d\d(([+-]\d\d:\d\d)|(\.\d{1,100}Z))?\s{1,100}({host}[\w.-]{1,2000})\s""",
    """THREAT,file,([^,]{0,2000},){8}(|({domain}[^\\,]{1,2000}))\\?(|({user}[^\\,]{1,2000}))(,|$)""",
    """THREAT,file,([^,]{0,2000},){7}(?:({user_email}[^@,]{1,2000}@[^\.,]{1,2000}\.[^,]{1,2000})|(?:|({domain}[^\\,]{1,2000}))\\?(?:|({user}[^\\,]{1,2000})))(,|$)""",
    """THREAT,file,([^,]{0,2000},){6}({alert_name}[^,]{1,2000})""",
    """({alert_type}file)""",
    """THREAT,file,((""|".*?[^"]"|[^,]{0,2000}),){31}({alert_id}\d{1,100})(,|$)""",
    """THREAT,file,([^,]{0,2000},){26}(("{0,20}[^"]{0,2000}")|[^,]{0,2000}),([^,]{0,2000},){28}"?({file_path}({file_parent}[^,"]{1,2000})\/[^,]{1,2000}?)\s{0,100}(,|$)""",
    """THREAT,file,((""|".*?[^"]"|[^,]{0,2000}),){26}"?(?:|({file_name}[^.",]{1,2000}?(\.({file_ext}[^,."?_]{1,5}))?))\s{0,100}("|,)""",
    """THREAT,file,([^,]{0,2000},){26}"?(?:|({file_name}[^.",]{1,2000}?(\.({file_ext}[^,."?_]{1,5}))?))\s{0,100}("|,)""",
    """THREAT,file,((""|"[^"]{1,2000}?"|[^,]{0,2000}),){26}("(?:|({file_name}[^."]{1,2000}?(\.({file_ext}[^,."?_]{1,5}))?))\s{0,100}",|("")?,)""",
    """THREAT,file,((""|"[^"]{1,2000}?"|[^,]{0,2000}),){29}({alert_severity}[^,]{1,2000})(,|$)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "file_name->malwareAttackerFile", "dest_ip->malwareAttackerIp", "action->description"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
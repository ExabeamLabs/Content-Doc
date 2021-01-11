#### Parser Content
```Java
{
Name = l-pan-file-alert
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "file-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,file,""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """THREAT,[^,]+,[^,]+,({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z),""",
    """THREAT,([^,]*,){3}({src_ip}[^,]*?),({dest_ip}[^,]*?),""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){25}({action}[^,]+)""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){54}({host}[\w\-\.]+)(,|$)""",
    """THREAT,file,([^,]*,){8}(|({domain}[^\\,]+))\\?(|({user}[^\\,]+))(,|$)""",
    """THREAT,file,([^,]*,){7}(?:({user_email}[^@,]+@[^\.,]+\.[^,]+)|(?:|({domain}[^\\,]+))\\?(?:|({user}[^\\,]+)))(,|$)""",
    """THREAT,file,([^,]*,){6}({alert_name}[^,]+)""",
    """({alert_type}file)""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){31}({alert_id}\d+)(,|$)""",
    """THREAT,file,([^,]*,){26}(("*[^"]*")|[^,]*),([^,]*,){28}"?({file_path}({file_parent}[^,"]+)\/[^,]+?)(,|$)""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){26}"?(?:|({file_name}[^.",]+?(\.({file_ext}[^,."?_]{1,5}))?))("|,)""",
    """THREAT,file,([^,]*,){26}"?(?:|({file_name}[^.",]+?(\.({file_ext}[^,."?_]{1,5}))?))("|,)""",
    """THREAT,file,((""|"[^"]+?"|[^,]*),){26}("(?:|({file_name}[^."]+?(\.({file_ext}[^,."?_]{1,5}))?))",|("")?,)""",
    """THREAT,file,((""|"[^"]+?"|[^,]*),){29}({alert_severity}[^,]+)(,|$)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "file_name->malwareAttackerFile", "dest_ip->malwareAttackerIp", "action->description"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
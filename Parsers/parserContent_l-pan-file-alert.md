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
    """exabeam_host=({host}[^\s]+)""",
    """THREAT,({alert_type}[^,]+),[^,]*,({time}\d\d\d\d/\d\d/\d\d \d\d:\d\d:\d\d),({src_ip}[\da-fA-F\.:]+),({dest_ip}[\da-fA-F\.:]+)(,|$)""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){25}({action}[^,]+)""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){54}({host}[\w\-\.]+)(,|$)""",
    """THREAT,file,([^,]*,){8}(|({domain}[^\\,]+))\\?(|({user}[^\\,]+))(,|$)""",
    """THREAT,file,([^,]*,){7}(|({domain}[^\\,]+))\\?(|({user}[^\\,]+))(,|$)""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){27}({alert_name}[^,]+)(,|$)""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){31}({alert_id}\d+)(,|$)""",
    """THREAT,file,([^,]*,){26}(("*[^"]*")|[^,]*),([^,]*,){28}"?({file_path}({file_parent}[^,"]+)\/.+?)\s*$""",
    ""","?({file_path}({file_parent}[^"][^,]*?[\\\/]+)?({file_name}[^\\\/]*?(\.({file_ext}\w+))?))"?\s*$""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){26}"?(?:|({file_name}.+?(\.({file_ext}[^,."?_]{1,5}))?))("|,)""",
    """THREAT,file,([^,]*,){26}"?(?:|({file_name}.+?(\.({file_ext}[^,."?_]{1,5}))?))("|,)""",
    """THREAT,file,((""|".*?[^"]"|[^,]*),){26}("(?:|({file_name}.+?[^"](\.({file_ext}[^,."?_]{1,5}))?))",|("")?,)"""
    """THREAT,file,((""|".*?[^"]"|[^,]*),){29}({alert_severity}[^,]+)(,|$)"""
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->malwareCategory", "file_name->malwareAttackerFile", "dest_ip->malwareAttackerIp", "action->description"]
    NameTemplate = """Palo Alto Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
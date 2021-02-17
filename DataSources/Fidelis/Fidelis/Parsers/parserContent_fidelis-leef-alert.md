#### Parser Content
```Java
{
Name = fidelis-leef-alert
  Vendor = Fidelis
  Product = Fidelis
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """LEEF:1.0|Fidelis Cybersecurity|""" ]
  Fields = [
             """devTime=({time}\d+)""",
	     """dvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """dvchost=({host}.+?)\s*(\w+=|$)""",
             """cs1=({alert_name}.+?)\s*(\w+=|$)""",
             """cs1=({alert_type}.+?)\s*(\w+=|$)""",
             """proto=(Unknown|({alert_type}.+?))\s*(\w+=|$)""",
	     """sev=({alert_severity}\d)""",
             """src=(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
             """(srcPort|spt)=({src_port}\d+)""",
             """dst=(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
	     """(dstPort|dpt)=({dest_port}\d+)""",
             """msg=\s*({additional_info}.+?)\s*(\w+=|$)""",
	     """target=(?:(<n\/a>)|({malware_url}.+?))\s*(\w+=|$)""",
	     """fname=(?:(<n\/a>)|({malware_url}.+?))\s*(\w+=|$).+?proto=SMB""",
       """duser=(?:(<n\/a>)|({target}.+?))(\s+\w+=|\s*$)""",
       """usrName=(?:(<n\/a>)|({user_email}.+?))(\s+\w+=|\s*$)""",
       """fname=(?:|(<n\/a>)|({process_name}.+?))\s+(\w+=|\s*$)"""
          ]
  DupFields = ["host->dest_host"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost", "malware_url->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
    NameTemplate = """Fidelis Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
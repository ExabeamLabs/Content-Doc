#### Parser Content
```Java
{
Name = fidelis-leef-alert
  Vendor = Fidelis
  Product = Fidelis XPS
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """LEEF:1.0|Fidelis Cybersecurity|""" ]
  Fields = [
             """devTime=({time}\d{1,100})""",
	     """dvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
             """dvchost=({host}.+?)\s{0,100}(\w+=|$)""",
             """cs1=({alert_name}.+?)\s{0,100}(\w+=|$)""",
             """cs1=({alert_type}.+?)\s{0,100}(\w+=|$)""",
             """proto=(Unknown|({alert_type}.+?))\s{0,100}(\w+=|$)""",
	     """sev=({alert_severity}\d)""",
             """src=(0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
             """(srcPort|spt)=({src_port}\d{1,100})""",
             """dst=(0.0.0.0|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
	     """(dstPort|dpt)=({dest_port}\d{1,100})""",
             """msg=\s{0,100}({additional_info}.+?)\s{0,100}(\w+=|$)""",
	     """target=(?:(<n\/a>)|({malware_url}.+?))\s{0,100}(\w+=|$)""",
	     """fname=(?:(<n\/a>)|({malware_url}.+?))\s{0,100}(\w+=|$).+?proto=SMB""",
       """duser=(?:(<n\/a>)|({target}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
       """usrName=(?:(<n\/a>)|({user_email}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
       """fname=(?:|(<n\/a>)|({process_name}.+?))\s{1,100}(\w+=|\s{0,100}$)"""
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
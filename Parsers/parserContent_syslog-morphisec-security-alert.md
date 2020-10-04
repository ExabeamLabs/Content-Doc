#### Parser Content
```Java
{
Name = syslog-morphisec-security-alert
  Vendor = Morphisec
  Product = Morphisec EPTP
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """"Protector IP":["""",""""Attack Time":["""",""""Attacked Module":[""""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d ({host}[\w.\-]+) Morphisec""",
    """"Protector IP":\["({src_ip}[a-fA-F\d.:]+)""",
    """"Message":\["({additional_info}[^"]+)"""",
    """({alert_name}attack)""",
    """"Logged In UserName":\["(({domain}[^\\\/"]+)[\\\/])?({user}[^\\\/"]+)"""",
    """"Attacked Module":\["({malware_url}[^"]+)"""",
    """"Attack Time":\["({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """"Computer Name":\["({src_host}[^"]+)"""",
  ]
  DupFields = ["alert_name->alert_type"]
}

{
  Name = cylance-protect-security-alert
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "M/d/yyyy H:mm:ss a"
  Conditions = [ """"Cylance Score"""", """"Malware - """, """"Tenant"""" ]
  Fields = [
    """"Access Time"+\s*:\s*"+({time}\d+\/\d+\/\d+\s+\d+:\d+:\d+\s+(AM|PM|am|pm))"+\s*[,\]\}]""",
    """"Device\s?Name"+\s*:\s*"+({host}([^"\\]|(\\\\)*\\"|\\[^"])+)"+\s*[,\]\}]""",
    """"Classification"+\s*:\s*"+({alert_name}([^"\\]|(\\\\)*\\"|\\[^"])+)"+\s*[,\]\}]""",
    """"File Owner"+\s*:\s*"+((N/A)|(({domain}[^\\]+)\\+({user}.+?)))"+\s*[,\]\}]""",
    """"File Status"+\s*:\s*"+({additional_info}([^"\\]|(\\\\)*\\"|\\[^"])+)"+\s*[,\]\}]""",
    """"Cylance Score"+\s*:\s*"+({alert_severity}([^"\\]|(\\\\)*\\"|\\[^"])+)"+\s*[,\]\}]""",
    """"File Path"+\s*:\s*"+({malware_url}([^"\\]|(\\\\)*\\"|\\[^"])+)"+\s*[,\]\}]""",
    """"File Name":"\s*({file_name}[^"]+)"""",
  ]
  DupFields = [ "alert_name->alert_type", "host->src_host" , "file_name->process_name"]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost", "alert_severity->sourceSeverity", "malware_url->malwareAttackerFile"]
    NameTemplate = """Cylance Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```
#### Parser Content
```Java
{
Name = cylance-protect-security-alert
  Vendor = Cylance
  Product = PROTECT
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
  ]
  DupFields = [ "alert_name->alert_type", "host->src_host" ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_type->malwareCategory", "src_host->malwareVictimHost", "alert_severity->sourceSeverity", "malware_url->malwareAttackerFile"]
    NameTemplate = """Cylance Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_host->host_name"]}
```
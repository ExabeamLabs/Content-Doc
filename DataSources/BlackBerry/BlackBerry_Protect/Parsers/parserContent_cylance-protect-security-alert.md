#### Parser Content
```Java
{
Name = cylance-protect-security-alert
  Vendor = BlackBerry
  Product = BlackBerry Protect
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "M/d/yyyy H:mm:ss a"
  Conditions = [ """"Cylance Score"""", """"Malware - """, """"Tenant"""" ]
  Fields = [
    """"Access Time"{1,20}\s{0,100}:\s{0,100}"{1,20}({time}\d{1,100}\/\d{1,100}\/\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))"{1,20}\s{0,100}[,\]\}]""",
    """"Device\s?Name"{1,20}\s{0,100}:\s{0,100}"{1,20}({host}([^"\\]|(\\\\)*\\"|\\[^"])+)"{1,20}\s{0,100}[,\]\}]""",
    """"Classification"{1,20}\s{0,100}:\s{0,100}"{1,20}({alert_name}([^"\\]|(\\\\)*\\"|\\[^"])+)"{1,20}\s{0,100}[,\]\}]""",
    """"File Owner"{1,20}\s{0,100}:\s{0,100}"{1,20}((N/A)|(({domain}[^\\]{1,2000})\\+({user}.+?)))"{1,20}\s{0,100}[,\]\}]""",
    """"File Status"{1,20}\s{0,100}:\s{0,100}"{1,20}({additional_info}([^"\\]|(\\\\)*\\"|\\[^"])+)"{1,20}\s{0,100}[,\]\}]""",
    """"Cylance Score"{1,20}\s{0,100}:\s{0,100}"{1,20}({alert_severity}([^"\\]|(\\\\)*\\"|\\[^"])+)"{1,20}\s{0,100}[,\]\}]""",
    """"File Path"{1,20}\s{0,100}:\s{0,100}"{1,20}({malware_url}([^"\\]|(\\\\)*\\"|\\[^"])+)"{1,20}\s{0,100}[,\]\}]""",
    """"File Name":"\s{0,100}({file_name}[^"]{1,2000})"""",
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
#### Parser Content
```Java
{
Name = syslog-symantec-mss-alert
  Vendor = Symantec
  Product = Symantec Managed Security Services
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Symantec MSS alert Conditions>""" ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """exabeam_raw=(?:"|')?\s{0,100}({alert_id}\d{1,100})\s{0,100}(?:"|')?,""",
    """exabeam_raw=(?:(?:\s{0,100}'(?:[^']|'')+')\s{0,100},|(?:\s{0,100}"(?:[^"]|"")+")\s{0,100},|[^",]{1,2000}?,|\s{0,100},|'',|"",)(?:"|')?({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d{1,100}(?:"|')?,""",
    """exabeam_raw=(?:(?:\s{0,100}'(?:[^']|'')+')\s{0,100},|(?:\s{0,100}"(?:[^"]|"")+")\s{0,100},|[^",]{1,2000}?,|\s{0,100},|'',|"",){3}"\s{0,100}({alert_severity}.+?)\s{0,100}",""",
    """exabeam_raw=(?:(?:\s{0,100}'(?:[^']|'')+')\s{0,100},|(?:\s{0,100}"(?:[^"]|"")+")\s{0,100},|[^",]{1,2000}?,|\s{0,100},|'',|"",){5}"\s{0,100}({alert_type}.+?)\s{0,100}",""",
    """exabeam_raw=(?:(?:\s{0,100}'(?:[^']|'')+')\s{0,100},|(?:\s{0,100}"(?:[^"]|"")+")\s{0,100},|[^",]{1,2000}?,|\s{0,100},|'',|"",){6}"\s{0,100}({alert_name}.+?)\s{0,100}",""",
    """exabeam_raw=(?:(?:\s{0,100}'(?:[^']|'')+')\s{0,100},|(?:\s{0,100}"(?:[^"]|"")+")\s{0,100},|[^",]{1,2000}?,|\s{0,100},|'',|"",){7}"?\s{0,100}({src_ip}.+?)\s{0,100}",""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->description"]
    NameTemplate = """Symantec Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
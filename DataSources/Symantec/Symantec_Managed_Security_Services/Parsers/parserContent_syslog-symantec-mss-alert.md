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
    """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
    """exabeam_raw=(?:"|')?\s*({alert_id}\d+)\s*(?:"|')?,""",
    """exabeam_raw=(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,|'',|"",)(?:"|')?({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\.\d+(?:"|')?,""",
    """exabeam_raw=(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,|'',|"",){3}"\s*({alert_severity}.+?)\s*",""",
    """exabeam_raw=(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,|'',|"",){5}"\s*({alert_type}.+?)\s*",""",
    """exabeam_raw=(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,|'',|"",){6}"\s*({alert_name}.+?)\s*",""",
    """exabeam_raw=(?:(?:\s*'(?:[^']|'')+')\s*,|(?:\s*"(?:[^"]|"")+")\s*,|[^",]+?,|\s*,|'',|"",){7}"?\s*({src_ip}.+?)\s*",""",
  ]
  SOAR {
    IncidentType = "malware"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_severity->sourceSeverity", "alert_id->sourceId", "src_ip->malwareVictimHost", "alert_type->description"]
    NameTemplate = """Symantec Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
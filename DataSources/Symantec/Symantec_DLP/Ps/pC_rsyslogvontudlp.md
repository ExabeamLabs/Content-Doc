#### Parser Content
```Java
{
Name = r-syslog-vontu-dlp
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Vontu Incident: """, """^^""" ]
  Fields = [
    """(exabeam_\w+=|^)({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """\s({host}[\w\.-]{1,2000})\s{1,100}Vontu Incident: """,
    """Vontu Incident:\s{1,100}({alert_name}.+?)\s{0,100}\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^)({alert_id}\d{1,100})\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){2}(N\/A|({subject}.+?))\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){3}(N\/A|({alert_severity}.+?))\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){6}(N\/A|({sender}[^@\^\s]{1,2000}@\S+?))\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){6}(N\/A|({os}[^:\^]{1,2000}):\/\/({domain}[^\/\^]{1,2000})\/({user}[^\^]{1,2000}?))\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){6}(N\/A|({src_ip}(\d{1,3}\.){3}\d{1,3}))\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){7}(N\/A|({recipients}({external_address}(?!\w+:\/\/)[^@\s]{1,2000}@({external_domain}\S+?))(,[^@\s]{1,2000}@\S+?)*))\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){7}(N\/A|({target}([^\^]|\^[^\^])+?))\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){7}(N\/A|\s{0,100}\w+:\/+({top_domain}[^\/\.\s]{1,2000}(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+)(\/\S+?)?)\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){8}(N\/A|({outcome}.+?))\^\^""",
    """Vontu Incident:\s{1,100}(([^\^]|\^[^\^])+?\^\^){13}(N\/A|({alert_type}.+?))\^\^""",
    """({direction}o)""",
  ]
  DupFields = [ "sender->user", "sender->original_user" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "src_ip->dlpDeviceName", "outcome->dlpActionTaken"]
    NameTemplate = """Vontu DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```
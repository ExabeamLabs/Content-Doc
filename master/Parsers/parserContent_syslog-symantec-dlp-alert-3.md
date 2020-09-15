#### Parser Content
```Java
{
Name = syslog-symantec-dlp-alert-3
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """,endpoint_machine=""", """,policy=""", """,incident_snapshot=""" ]
  Fields = [
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d\d\d[+-]\d\d:\d\d\s+({host}[\w\-.]+)""",
    """(?i)incident_id="*({alert_id}\d+)""",
    """(?i)policy="*({alert_name}[^",]+)("|,|\s*$)""",
    """(?i)protocol="*({protocol}[^",]+)("|,|\s*$)""",
    """(?i)recipients="*(?=[\w.]+@[\w.])({recipients}[^",]+)("|,|\s*$)""",
    """(?i)recipients="*(?=[\w.]+@[\w.])({external_address}[^",]+)("|,|\s*$)""",
    """(?i)recipients="*[^@]+@({external_domain}[^,"@]+)("|,|\s*$)""",
    """(?i)recipients="*(?=\w+:\/+)({target}[^",]+)("|,|\s*$)""",
    """(?i)sender="*(?=[\w.]+@[\w.])({sender}[^",]+)("|,|\s*$)""",
    """(?i)sender="*(?=[\w.]+@[\w.])({user}[^",]+)("|,|\s*$)""",
    """(?i)severity="*({alert_severity}[^",]+)("|,|\s*$)""",
    """(?i)subject="*(?:N\/A|({subject}[^",]+))("|,|\s*$)""",
    """\s(?i)file_name="*(?:N\/A|({file_name}[^",]+))\s*("|,|\s*$)""",
    """(?i)blocked="*(?:N\/A|None|({outcome}[^",]+))("|,|\s*$)""",
    """(?i)endpoint_machine="*(N\/A|({dest_host}[^",]+))("|,|\s*$)""",
    """(?i)endpoint_user_name="*\s*(N\/A|(({domain}[^\\]+)\\+)?({user}[^\s",]+))("|,|\s*$)""",
    """(?i)endpoint_user_name="*\s*(N\/A|({user}[^\s",@]+)@({domain}[^\s",@]+))""",
    """(?i)incident_snapshot=[^,]*?({alert_id}\d+),""",
    """(?i)incident_snapshot="*(\w+:\/+)?[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|local))+))(\/|\||"|\s+\w+=|\s*$)"""

    """(?i)machineIP="*(N\/A|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
  ]
  DupFields = [ "alert_name->alert_type", "external_address->recipient" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "dest_host->dlpDeviceName", "outcome->dlpActionTaken"]
    NameTemplate = """Vontu DLP Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address","dest_host->host_name"]}
```
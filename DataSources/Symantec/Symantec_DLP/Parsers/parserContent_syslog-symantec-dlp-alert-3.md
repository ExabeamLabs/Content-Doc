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
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d\d\d[+-]\d\d:\d\d\s{1,100}({host}[\w\-.]+)""",
    """(?i)incident_id="{0,20}({alert_id}\d{1,100})""",
    """(?i)policy="{0,20}({alert_name}[^",]+)("|,|\s{0,100}$)""",
    """(?i)protocol="{0,20}({protocol}[^",]+)("|,|\s{0,100}$)""",
    """(?i)recipients="{0,20}(?=[\w.]+@[\w.])({recipients}[^",]+)("|,|\s{0,100}$)""",
    """(?i)recipients="{0,20}(?=[\w.]+@[\w.])({external_address}[^",]+)("|,|\s{0,100}$)""",
    """(?i)recipients="{0,20}[^@]+@({external_domain}[^,"@]+)("|,|\s{0,100}$)""",
    """(?i)recipients="{0,20}(?=\w+:\/+)({target}[^",]+)("|,|\s{0,100}$)""",
    """(?i)sender="{0,20}(?=[\w.]+@[\w.])({sender}[^",]+)("|,|\s{0,100}$)""",
    """(?i)sender="{0,20}(?=[\w.]+@[\w.])({user}[^",]+)("|,|\s{0,100}$)""",
    """(?i)severity="{0,20}({alert_severity}[^",]+)("|,|\s{0,100}$)""",
    """(?i)subject="{0,20}(?:N\/A|({subject}[^",]+))("|,|\s{0,100}$)""",
    """\s(?i)file_name="{0,20}(?:N\/A|({file_name}[^",]+))\s{0,100}("|,|\s{0,100}$)""",
    """(?i)blocked="{0,20}(?:N\/A|None|({outcome}[^",]+))("|,|\s{0,100}$)""",
    """(?i)endpoint_machine="{0,20}(N\/A|({dest_host}[^",]+))("|,|\s{0,100}$)""",
    """(?i)endpoint_user_name="{0,20}\s{0,100}(N\/A|(({domain}[^\\]+)\\+)?({user}[^\s",]+))("|,|\s{0,100}$)""",
    """(?i)endpoint_user_name="{0,20}\s{0,100}(N\/A|({user}[^\s",@]+)@({domain}[^\s",@]+))""",
    """(?i)incident_snapshot=[^,]*?({alert_id}\d{1,100}),""",
    """(?i)incident_snapshot="{0,20}(\w+:\/+)?[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|local))+))(\/|\||"|\s{1,100}\w+=|\s{0,100}$)"""

    """(?i)machineIP="{0,20}(N\/A|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
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
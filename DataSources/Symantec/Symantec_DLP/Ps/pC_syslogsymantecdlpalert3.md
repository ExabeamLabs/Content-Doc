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
    """({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\d)\d\d\d[+-]\d\d:\d\d\s{1,100}({host}[\w\-.]{1,2000})""",
    """(?i)incident_id="{0,20}({alert_id}\d{1,100})""",
    """(?i)policy="{0,20}({alert_name}[^",]{1,2000})("|,|\s{0,100}$)""",
    """(?i)protocol="{0,20}({protocol}[^",]{1,2000})("|,|\s{0,100}$)""",
    """(?i)recipients="{0,20}(?=[\w.]{1,2000}@[\w.])({recipients}[^",]{1,2000})("|,|\s{0,100}$)""",
    """(?i)recipients="{0,20}(?=[\w.]{1,2000}@[\w.])({external_address}[^",]{1,2000})("|,|\s{0,100}$)""",
    """(?i)recipients="{0,20}[^@]{1,2000}@({external_domain}[^,"@]{1,2000})("|,|\s{0,100}$)""",
    """(?i)recipients="{0,20}(?=\w+:\/+)({target}[^",]{1,2000})("|,|\s{0,100}$)""",
    """(?i)sender="{0,20}(?=[\w.]{1,2000}@[\w.])({sender}[^",]{1,2000})("|,|\s{0,100}$)""",
    """(?i)sender="{0,20}(?=[\w.]{1,2000}@[\w.])({user}[^",]{1,2000})("|,|\s{0,100}$)""",
    """(?i)severity="{0,20}({alert_severity}[^",]{1,2000})("|,|\s{0,100}$)""",
    """(?i)subject="{0,20}(?:N\/A|({subject}[^",]{1,2000}))("|,|\s{0,100}$)""",
    """\s(?i)file_name="{0,20}(?:N\/A|({file_name}[^",]{1,2000}))\s{0,100}("|,|\s{0,100}$)""",
    """(?i)blocked="{0,20}(?:N\/A|None|({outcome}[^",]{1,2000}))("|,|\s{0,100}$)""",
    """(?i)endpoint_machine="{0,20}(N\/A|({dest_host}[^",]{1,2000}))("|,|\s{0,100}$)""",
    """(?i)endpoint_user_name="{0,20}\s{0,100}(N\/A|(({domain}[^\\]{1,2000})\\+)?({user}[^\s",]{1,2000}))("|,|\s{0,100}$)""",
    """(?i)endpoint_user_name="{0,20}\s{0,100}(N\/A|({user}[^\s",@]{1,2000})@({domain}[^\s",@]{1,2000}))""",
    """(?i)incident_snapshot=[^,]{0,2000}?({alert_id}\d{1,100}),""",
    """(?i)incident_snapshot="{0,20}(\w+:\/+)?[^\s]{0,2000}?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]{1,2000}(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za|local))+))(\/|\||"|\s{1,100}\w+=|\s{0,100}$)"""

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
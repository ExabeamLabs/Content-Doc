#### Parser Content
```Java
{
Name = q-symantec-dlp-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "MMM dd',' yyyy HH:mm:ss a"
  Conditions = [ """Symantec|DLP|""", """|policy=""", """|incidentSnapshot=""" ]
  Fields = [
    """exabeam_endTime=({time}\d+)""",
    """\|occurredon=({time}[^\|]+?)\s*(\||$)""",
    """({host}[\w.\-]+)\s+Symantec\|DLP\|""",
    """\|severity=({alert_severity}[^\|]+)""",
    """\|policy=({alert_name}[^\|]+)""",
    """\|policy=([^-\|]*\-)?\s*({alert_type}[^\|]+)""",
    """\|rules=({rules}[^\|]+)""",
    """\|action=(None|({outcome}[^\|]+))""",
    """\|incidentID=({alert_id}\d+)""",
    """\|protocol=({protocol}[^\|]+?)\s*(\||$)""",
    """\|subject=((?!SFTP|HTTP|FTP|TCP|N\/A)({subject}[^\|]+))""",
    """\|fileName=(?!https:|N\/A).*?({file_name}[^\|]+)""",
    """\|AttachmentName=(N\/A|({file_name}[^\|]+?))\s*(\||$)""",
    """\|endpointusrname=(N\/A|(({domain}[^\\]+)\\+)?({user}[^\s\|]+))""",
    """\|Username=(N\/A|(({domain}[^\\\|]+)\\+)?({user}[^\s\|]+))""",
    """\|subject.*?\|Username=(N\/A|(({domain}[^\\]+)\\+)?({user}[^\s\|]+))""",
    """\|(Username|src)=({user}[^\s@\|]+@[^@\s\|]+)""",
    """\|(Username|src)=WinNT:\/+({domain}[^\\\/\|]+)(\\|\/)+({user}[^\s\|]+)""",
    """\|endpointhostname=(N\/A|({src_host}[\w\-.]+))""",
    """\|endpointipaddress=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\|sender=(?=[\w.]+@[\w.])({sender}[^\|]+)""",
    """\|sender=(?=[\w.]+@[\w.])({user}[^\|]+)""",
    """\|EmailAddress=({user_email}[^\|]+?)\s*(\||$)""",
    """\|recipients=({target}[^\|]+?)\s*(\||$)""",
    """\|destination=({target}[^\|]+?)\s*(\||$)""",
    """\|incidentSnapshot=\w+:\/+[^\s]*?((?!\d{1,3}\.\d{1,3}\.\d{1,3})({top_domain}[^\/\.\s]+(\.(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))(\/|\|)""",
    """\|matchCount=({match_count}[^\|]+?)\s*(\||$)""",
  ]
  DupFields = [ "protocol->alert_type" ]
  SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "file_name->dlpFileName",  "outcome->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="dest_address", Fields=["dest_ip->ip_address","dest_host->host_name"]}
```
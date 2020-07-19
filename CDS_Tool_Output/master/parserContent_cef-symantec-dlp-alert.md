#### Parser Content
```Java
{
Name = cef-symantec-dlp-alert
    Vendor = Symantec
    Product = Symantec DLP
    Lms = ArcSight
    DataType = "dlp-alert"
    TimeFormat = "epoch"
    Conditions = [ """CEF""","""|Symantec|DLP|""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """({host}[\w\-.]+)\s+CEF:""",
      """\srt=({time}\d+)""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[\w.\-]+)""",
      """\ssuser=(({domain}[^\\=]+)\\+)?({user}.+?)\s\w+=""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\shost=({src_host}.+?)\s\w+=""",
      """\W(externalId|INCIDENT_ID)=({alert_id}\d+)""",
      """\|Symantec\|DLP\|([^|]*\|){3}({alert_severity}[^|]+)\|""",
      """\|Symantec\|DLP\|([^|]*\|){2}({alert_name}[^|]+)\|""",
      """\|Symantec\|DLP\|([^|]*\|){2}({alert_type}[^|]+)\|""",
      """\|Symantec\|DLP\|([^|]*\|){2}.*?({protocol}[^\s|]+)\|""",
      """\sdeviceSeverity=\d:({alert_severity}.+?)\s\w+=""",
      """\scat=({alert_type}.+?)\s\w+=""",
      """\sapp=({alert_type}.+?)\s\w+=""",
      """\sfname=(?:N\/A|({file_name}.+?))\s\w+=""",
      """\sfilePath=(?:N\/A|({directory}.+?))\s\w+=""",
      """\smsg=(?:N\/A|({additional_info}.+?))\s\w+=""",
      """\W(act|BLOCKED)=(?:None|({outcome}.+?))\s\w+=""",
      """\WSENDER=({user_email}[^\s@]+@[^\s@]+)\s+(\w+=|$)""",
      """\WSENDER=(N\/A|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|[^\s@]*?(({domain}[^\\\/\s@]+)[\\\/]+)?({user}[^\\\/\s@]+))\s+(\w+=|$)""",
      """\WENDPOINT_MACHINE=({src_host}[\w\-.]+)\s+(\w+=|$)""",
      """\WPROTOCOL=(N\/A|({protocol}.+?))\s+(\w+=|$)""",
    ]
    DupFields = ["user_email->sender"]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_host->dlpDeviceName", "file_name->dlpFileName", "outcome->dlpActionTaken"]
      NameTemplate = """Symantec DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```
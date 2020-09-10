#### Parser Content
```Java
{
Name = s-vontu-dlp-alert
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """| app=symantec:dlp:incident""","""| Manager_Email=""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """exabeam_raw=.*?\d\d:\d\d:\d\d ({host}[^\s]+)\s+""",
      """incident_id="({alert_id}\d+)"""",
      """\|\spolicy="({alert_name}[^"]+)"""",
      """\|\sseverity="({alert_severity}[^"]+)"""",
      """\|\sprotocol="({alert_type}[^"]+)"""",
      """\|\ssender="(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({os}\w+):\/+({domain}[^\/]+)\/({user}[^"]+))"""",
      """\|\sprotocol="({protocol}[^"]+)"""",
      """\|\srecipient="(((({account}[^@]+)@)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))|({target}[^"]+))"""",
      """\|\sBusiness_Unit="({additional_info}[^"]+)""""
    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_ip->dlpDeviceName",  "alert_type->dlpActionTaken"]
      NameTemplate = """Vontu DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
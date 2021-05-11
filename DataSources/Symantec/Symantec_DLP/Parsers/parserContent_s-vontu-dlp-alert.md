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
      """exabeam_raw=.*?\d\d:\d\d:\d\d ({host}[^\s]+)\s{1,100}""",
      """incident_id="({alert_id}\d{1,100})"""",
      """\|\spolicy="({alert_name}[^"]+)"""",
      """\|\sseverity="({alert_severity}[^"]+)"""",
      """\|\sprotocol="({alert_type}[^"]+)"""",
      """\|\incident_type="({alert_type}[^"]+)""",
      """\|\ssender="(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({os}\w+):\/+({domain}[^\/]+)\/({user}[^"]+))"""",
      """\|\sprotocol="({protocol}[^"]+)"""",
      """\|\srecipient="(((({account}[^@]+)@)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))|(N/A|(?i)Unknown|({target}[^"]+)))"""",
      """\|\sBusiness_Unit="({additional_info}[^"]+)"""",
      """\|\sRR_Action="({outcome}[^"]+)""",
      """\|\smatch_count="({match_count}\d{1,100})""",
      """\|\sfilename="(N/A|({file_path}({file_parent}(?:[^"]+)?[\\\/])?({file_name}[^\\\/"]+?)))\s{0,100}"""",
      """\|\sEP_Machine="({src_host}[^"]+)""",
      """\|\sEP_IP="({src_ip}[a-fA-F:\d.]+)"""

    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_ip->dlpDeviceName",  "alert_type->dlpActionTaken"]
      NameTemplate = """Vontu DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
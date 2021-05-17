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
      """exabeam_host=({host}[^\s]{1,2000})""",
      """exabeam_raw=.*?\d\d:\d\d:\d\d ({host}[^\s]{1,2000})\s{1,100}""",
      """incident_id="({alert_id}\d{1,100})"""",
      """\|\spolicy="({alert_name}[^"]{1,2000})"""",
      """\|\sseverity="({alert_severity}[^"]{1,2000})"""",
      """\|\sprotocol="({alert_type}[^"]{1,2000})"""",
      """\|\incident_type="({alert_type}[^"]{1,2000})""",
      """\|\ssender="(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({os}\w+):\/+({domain}[^\/]{1,2000})\/({user}[^"]{1,2000}))"""",
      """\|\sprotocol="({protocol}[^"]{1,2000})"""",
      """\|\srecipient="(((({account}[^@]{1,2000})@)?({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))|(N/A|(?i)Unknown|({target}[^"]{1,2000})))"""",
      """\|\sBusiness_Unit="({additional_info}[^"]{1,2000})"""",
      """\|\sRR_Action="({outcome}[^"]{1,2000})""",
      """\|\smatch_count="({match_count}\d{1,100})""",
      """\|\sfilename="(N/A|({file_path}({file_parent}(?:[^"]{1,2000})?[\\\/])?({file_name}[^\\\/"]{1,2000}?)))\s{0,100}"""",
      """\|\sEP_Machine="({src_host}[^"]{1,2000})""",
      """\|\sEP_IP="({src_ip}[a-fA-F:\d.]{1,2000})"""

    ]
    SOAR {
      IncidentType = "dlp"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "user->dlpUser", "alert_name->dlpPolicy", "alert_severity->sourceSeverity", "protocol->dlpProtocol", "src_ip->dlpDeviceName",  "alert_type->dlpActionTaken"]
      NameTemplate = """Vontu DLP Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
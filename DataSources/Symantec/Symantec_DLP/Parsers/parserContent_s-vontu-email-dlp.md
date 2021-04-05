#### Parser Content
```Java
{
Name = s-vontu-email-dlp
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """| app=symantec:dlp:incident""","""| protocol="SMTP"|""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""", 
      """incident_id="({alert_id}\d+)"""",
      """\|\spolicy="({alert_name}[^"]+)"""",
      """\|\sseverity="({alert_severity}[^"]+)"""",
      """\|\spolicy_rule="({policy}[^"]+?)\s*"""",
      """\|\spolicy="[^"]+\-\s*({alert_type}[^"]+)""", 
      """\|\sUserID="({user}[^"]+)"""",
      """\|\ssender="({sender}[^"]+)"""",
      """\|\ssubject="\s*(N/A|({subject}[^"]+?))\s*"""",
      """\|\sprotocol="({protocol}[^"]+)"""",
      """\|\srecipient="({recipients}[^"]+)"""",
      """\|\srecipient="({external_address}[^,"]+)""",
      """\|\srecipient="[^@]+@({external_domain}[^,"]+)""",
      """\|\sBusiness_Unit="({additional_info}[^"]+)"""",
      """\|\sfilename="(N/A|(?i)unknown|({target}[^"]+?))\s*"""",
      """\|\sfilename="(N/A|(?i)unknown|({file_name}[^"]+?\.\w+))""",
      """\|\sRR_Action="({outcome}[^"]+)""",
      """\|\smatch_count="({match_count}\d+)""",
      """\|\sEP_Machine="({src_host}[^"]+)""",
      """\|\sEP_IP="({src_ip}[a-fA-F:\d.]+)"""
    ]
  }
```
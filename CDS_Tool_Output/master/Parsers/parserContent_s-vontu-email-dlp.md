#### Parser Content
```Java
{
Name = s-vontu-email-dlp
    Vendor = Symantec
    Product = Symantec DLP
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """| app=symantec:dlp:incident""","""| protocol="SMTP"|""" ]
    Fields = [
      """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
      """exabeam_host=({host}[^\s]+)""",
      """exabeam_raw=.*?\d\d:\d\d:\d\d ({host}[^\s]+)\s+""",
      """incident_id="({alert_id}\d+)"""",
      """\|\spolicy="({alert_name}[^"]+)"""",
      """\|\sseverity="({alert_severity}[^"]+)"""",
      """\|\sprotocol="({alert_type}[^"]+)"""",
      """\|\ssender="({user}[^@"]+)@[^"]+"""",
      """\|\ssender="({sender}[^"]+)"""",
      """\|\ssubject="({subject}[^"]+)"""",
      """\|\sprotocol="({protocol}[^"]+)"""",
      """\|\srecipient="({recipients}[^"]+)"""",
      """\|\srecipient="({external_address}[^,"]+)""",
      """\|\srecipient="[^@]+@({external_domain}[^,"]+)""",
      """\|\sBusiness_Unit="({additional_info}[^"]+)"""",
    ]
  }
```
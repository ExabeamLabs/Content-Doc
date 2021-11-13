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
      """exabeam_host=({host}[^\s]{1,2000})""", 
      """incident_id="({alert_id}\d{1,100})"""",
      """\|\spolicy="({alert_name}[^"]{1,2000})"""",
      """\|\sseverity="({alert_severity}[^"]{1,2000})"""",
      """\|\spolicy_rule="({policy}[^"]{1,2000}?)\s{0,100}"""",
      """\|\spolicy="[^"]{1,2000}\-\s{0,100}({alert_type}[^"]{1,2000})""", 
      """\|\sUserID="({user}[^"]{1,2000})"""",
      """\|\ssender="({sender}[^"]{1,2000})"""",
      """\|\ssubject="\s{0,100}(N/A|({subject}[^"]{1,2000}?))\s{0,100}"""",
      """\|\sprotocol="({protocol}[^"]{1,2000})"""",
      """\|\srecipient="({recipients}[^"]{1,2000})"""",
      """\|\srecipient="({external_address}[^,"]{1,2000})""",
      """\|\sBusiness_Unit="({additional_info}[^"]{1,2000})"""",
      """\|\sfilename="(N/A|(?i)unknown|({target}[^"]{1,2000}?))\s{0,100}"""",
      """\|\sfilename="(N/A|(?i)unknown|({file_name}[^"]{1,2000}?\.\w+))""",
      """\|\sRR_Action="({outcome}[^"]{1,2000})""",
      """\|\smatch_count="({match_count}\d{1,100})""",
      """\|\sEP_Machine="({src_host}[^"]{1,2000})""",
      """\|\sEP_IP="({src_ip}[a-fA-F:\d.]{1,2000})"""
    ]
  

}
```
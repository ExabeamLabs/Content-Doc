#### Parser Content
```Java
{
Name = cef-mcafee-epo-alert-2
  Conditions = [ """CEF""","""|McAfee|ePolicy Orchestrator|""", """The user was not authorized to access the requested URL""" ]
  Fields = ${McAfeeParserTemplates.cef-mcafee-epo-alert.Fields}[
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\seventId=({alert_id}\d{1,100})""",
    """\scatdt=({alert_type}.*?)\s{1,100}(\w+=|$)""",
  ]
}
cef-mcafee-epo-alert = {
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\sdhost=({src_host}[^\s]{1,2000})""",
    """\sdst=(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sfname=({malware_url}.+?)\s{1,100}(\w+=)""",
    """\sfname=({malware_url}[^=]{1,2000}?\\+({malware_file_name}[^\\=]{1,2000}?))\s{1,100}\w+=""",
    """\sduser=(SYSTEM|N\/A|(({domain}[^=\\]{1,2000})\\+)?({user}.+?))\s{1,100}(\w+=|$)""",
    """\sdntdom=(?:\(none\)|({domain}[^\s]{1,2000}))""",
    """\seventId=({alert_id}\d{1,100})""",
    """\sexternalId=({alert_id}\d{1,100})""",
    """\|McAfee\|ePolicy[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^.|]{1,2000})""",
    """\scs1=(?:none|({alert_name}.+?))\s{1,100}(\w+=|$)""",
    """\scat=({threat_category}.+?)\s{1,100}(\w+=|$)""",
    """\|McAfee\|ePolicy[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}[^.|]{1,2000})""",
    """\|McAfee\|ePolicy[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_severity}[^\|]{1,2000})""",
    """\scategoryOutcome=/?({outcome}.+?)\s{1,100}(\w+=|$)""",
  ]

```
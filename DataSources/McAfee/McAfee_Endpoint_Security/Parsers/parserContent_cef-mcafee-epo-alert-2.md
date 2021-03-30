#### Parser Content
```Java
{
Name = cef-mcafee-epo-alert-2
  Conditions = [ """CEF""","""|McAfee|ePolicy Orchestrator|""", """The user was not authorized to access the requested URL""" ]
  Fields = ${McAfeeParserTemplates.cef-mcafee-epo-alert.Fields}[
    """exabeam_host=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s+(\w+=|$)""",
    """\seventId=({alert_id}\d+)""",
    """\scatdt=({alert_type}.*?)\s+(\w+=|$)""",
  ]
}
cef-mcafee-epo-alert = {
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\sdhost=({src_host}[^\s]+)""",
    """\sdst=(?:0.0.0.0|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\sfname=({malware_url}.+?)\s+(\w+=)""",
    """\sfname=({malware_url}[^=]+?\\+({malware_file_name}[^\\=]+?))\s+\w+=""",
    """\sduser=(SYSTEM|N\/A|(({domain}[^=\\]+)\\+)?({user}.+?))\s+(\w+=|$)""",
    """\sdntdom=(?:\(none\)|({domain}[^\s]+))""",
    """\seventId=({alert_id}\d+)""",
    """\sexternalId=({alert_id}\d+)""",
    """\|McAfee\|ePolicy.+?\|.+?\|.+?\|({alert_name}[^.|]+)""",
    """\scs1=(?:none|({alert_name}.+?))\s+(\w+=|$)""",
    """\scat=({threat_category}.+?)\s+(\w+=|$)""",
    """\|McAfee\|ePolicy.+?\|.+?\|.+?\|({alert_type}[^.|]+)""",
    """\|McAfee\|ePolicy.+?\|.+?\|.+?\|.+?\|({alert_severity}[^\|]+)""",
    """\scategoryOutcome=/?({outcome}.+?)\s+(\w+=|$)""",
  ]

```
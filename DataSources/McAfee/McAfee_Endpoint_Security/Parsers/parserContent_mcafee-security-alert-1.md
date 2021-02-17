#### Parser Content
```Java
{
Name = mcafee-security-alert-1
  DataType = "alert"
  Conditions = [ """DetectingProductName=McAfee Host Intrusion Prevention""" ]
  Fields = ${McAfeeParserTemplates.mcafee-dlp-alert.Fields}[
    """\WWorkstation Name=({host}[^,]+)""",
    """\WThreatEventID=({alert_id}\d+)""",
    """\WThreatType=({alert_type}[^,]+)""",
      """,ThreatSourceUserName=(({domain}[^,\\\/]+)[\\\/]+)?({user}[^,\\\/]+),""",
    """\WThreatSourceURL=({malware_url}[^,]+)""",
  ]
}
```
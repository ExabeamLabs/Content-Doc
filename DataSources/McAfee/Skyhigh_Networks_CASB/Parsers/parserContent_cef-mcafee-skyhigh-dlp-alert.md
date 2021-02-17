#### Parser Content
```Java
{
Name = cef-mcafee-skyhigh-dlp-alert
    Vendor = McAfee
    Product = Skyhigh Networks CASB
    Lms = ArcSight
    DataType = "dlp-alert"
    TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
    Conditions = [ """|McAfee (Skyhigh)|Anomalies|""" ]
    Fields = [
      """\Wcat=(|({alert_type}.+?))(\s+\w+=|\s*$)""",
      """({host}[\w.\-]+)\s+(LEEF|CEF):""",
      """CEF:([^\|]*\|){5}({alert_type}[^\|\s]+)\|""",
      """\W(start|devTime)=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d+ \w+)""",
      """\W(suser|usrName)=(N\/A|({user_email}[^@=]+?@[^@=]+?)|({user}(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\s]+?))(\s+\w+=|\s*$)""",
      """\W(riskSeverity|sev)=({alert_severity}\w+)""",
      """\WpolicyName=(null|({alert_name}.+?))(\s+\w+=|\s*$)""",
      """\W(response|status)=(|({outcome}.+?))(\s+\w+=|\s*$)""",
      """\WincidentId=({alert_id}\d+)""",
      """\WserviceNames=(|({additional_info}.+?))(\s+\w+=|\s*$)""",
      """\WcontentItemName=(|({malware_file_name}.+?))(\s+\w+=|\s*$)""",
      """\WtotalMatchCount=(|({total_match_count}.+?))(\s+\w+=|\s*$)"""
    ]
  }
```
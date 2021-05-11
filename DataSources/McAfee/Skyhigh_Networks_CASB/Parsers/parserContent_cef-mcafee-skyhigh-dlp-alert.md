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
      """\Wcat=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """({host}[\w.\-]+)\s{1,100}(LEEF|CEF):""",
      """CEF:([^\|]*\|){5}({alert_type}[^\|\s]+)\|""",
      """\W(start|devTime)=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d\.\d{1,100} \w+)""",
      """\W(suser|usrName)=(N\/A|({user_email}[^@=]+?@[^@=]+?)|({user}(?!\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[^\s]+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\W(riskSeverity|sev)=({alert_severity}\w+)""",
      """\WpolicyName=(null|({alert_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\W(response|status)=(|({outcome}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WincidentId=({alert_id}\d{1,100})""",
      """\WserviceNames=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WcontentItemName=(|({malware_file_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
      """\WtotalMatchCount=(|({total_match_count}.+?))(\s{1,100}\w+=|\s{0,100}$)"""
    ]
  }
```
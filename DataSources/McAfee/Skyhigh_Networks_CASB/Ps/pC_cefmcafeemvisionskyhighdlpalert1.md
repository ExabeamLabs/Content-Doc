#### Parser Content
```Java
{
Name = cef-mcafee-mvision-skyhigh-dlp-alert-1
  Vendor = McAfee
  Product = Skyhigh Networks CASB
  Lms = ArcSight
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CEF:0|McAfee""", """MVISION Cloud""", """|Dlp|Alert.Policy|"""]
  Fields = [
    """\d\d:\d\d:\d\d\s({host}[^\s]{1,2000})\s{1,100}CEF:""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """riskSeverity=({alert_severity}[^\s]{1,2000})""",
    """Dlp\|({alert_type}Alert\.Policy)\|""",
    """contentItemName=({file_name}[^=]{1,2000})\s{1,100}\w+=""",
    """contentItemHierarchy=({additional_info}[^=]{1,2000})\s{1,100}\w+=""",
    """incidentId=({alert_id}[^=]{1,2000}?)\s\w{1,100}=""",
    """suser=(N\/A|({user_email}[^@\s]{1,2000}@({email_domain}[^\.]{1,2000}\.[^\s]{1,2000})))\s{1,100}\w+=""",
    """response=\[({outcome}[^\]]{1,2000})\]\s{1,100}\w+=""",
    """policyName=({alert_name}[^=]{1,2000})\s{1,100}\w+=""",
    """serviceNames=\[({target}[^=]{1,2000})\]\s{1,100}\w+=""",
    """totalMatchCount=({total_match_count}\d{1,100})\s{1,100}\w+=""",
    ]
}
}
```
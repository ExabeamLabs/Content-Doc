#### Parser Content
```Java
{
Name = cef-mcafee-dlp-alert-info
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "dlp-alert"
      TimeFormat = "epoch"
      Conditions = [ """McAfee|Data Loss Prevention""", """|Administrative: """ ]
      Fields = [
        """exabeam_host=({host}[^\s]{1,2000})""",
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """CEF:(.*?\|){4}({alert_type}.*?)\|"""
        """CEF:(.*?\|){5}({alert_name}.*?)\|"""
        """CEF:(.*?\|){6}({alert_severity}.*?)\|"""
        """(\s|\|)deviceSeverity=({alert_severity}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)ad.PrimaryUserAccountID=({user}[^\|\s@]{1,2000})""",
        """(\s|\|)suser=({user}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)categoryOutcome=(\/)?({outcome}[^\|\s]{1,2000})"""
        """(\s|\|)eventId=({alert_id}\d{1,100})\s"""
      ]
    }
```
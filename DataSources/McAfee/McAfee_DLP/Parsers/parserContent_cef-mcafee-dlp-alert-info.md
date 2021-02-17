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
        """exabeam_host=({host}[^\s]+)""",
        """(\s|\|)rt=({time}.+?)\s+([\w\.-]+=|$)""",
        """CEF:(.*?\|){4}({alert_type}.*?)\|"""
        """CEF:(.*?\|){5}({alert_name}.*?)\|"""
        """CEF:(.*?\|){6}({alert_severity}.*?)\|"""
        """(\s|\|)deviceSeverity=({alert_severity}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)ad.PrimaryUserAccountID=({user}[^\|\s@]+)""",
        """(\s|\|)suser=({user}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)categoryOutcome=(\/)?({outcome}[^\|\s]+)"""
        """(\s|\|)eventId=({alert_id}\d+)\s"""
      ]
    }
```
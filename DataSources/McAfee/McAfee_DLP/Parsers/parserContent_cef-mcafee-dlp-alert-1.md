#### Parser Content
```Java
{
Name = cef-mcafee-dlp-alert-1
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "dlp-alert"
      TimeFormat = "epoch"
      Conditions = [ """McAfee|Data Loss Prevention""", """|dlp """ ]
      Fields = [
        """exabeam_host=({host}[^\s]+)""",
        """(\s|\|)rt=({time}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)deviceSeverity=({alert_severity}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)suser=({user}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)sproc=({process_name}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)fname=({file_name}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)filePath=({file_path}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)cs5=({target}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)request=({target}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)cs1=({additional_info}.+?)\s+([\w\.-]+=|$)"""
 
        """({alert_type}DLP: Web Post Protection)""", 
        """(\s|\|)cs1=({alert_name}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)ad\.IncidentId\.l=({alert_id}\d+)\s""",
        """(\s|\|)act=({outcome}[^=]+?)\s+([\w\.-]+=|$)"""
      ]
    }
```
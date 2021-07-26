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
        """exabeam_host=({host}[^\s]{1,2000})""",
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)deviceSeverity=({alert_severity}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)suser=({user}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)sproc=({process_name}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fname=({file_name}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)filePath=({file_path}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)cs5=({target}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)request=({target}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)cs1=({additional_info}.+?)\s{1,100}([\w\.-]{1,2000}=|$)"""
 
        """({alert_type}DLP: Web Post Protection)""", 
        """(\s|\|)cs1=({alert_name}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)ad\.IncidentId\.l=({alert_id}\d{1,100})\s""",
        """(\s|\|)act=({outcome}[^=]{1,2000}?)\s{1,100}([\w\.-]{1,2000}=|$)"""
      ]
    }
```
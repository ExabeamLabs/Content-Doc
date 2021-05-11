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
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)deviceSeverity=({alert_severity}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)suser=({user}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)sproc=({process_name}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)fname=({file_name}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)filePath=({file_path}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)cs5=({target}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)request=({target}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)cs1=({additional_info}.+?)\s{1,100}([\w\.-]+=|$)"""
 
        """({alert_type}DLP: Web Post Protection)""", 
        """(\s|\|)cs1=({alert_name}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)ad\.IncidentId\.l=({alert_id}\d{1,100})\s""",
        """(\s|\|)act=({outcome}[^=]+?)\s{1,100}([\w\.-]+=|$)"""
      ]
    }
```
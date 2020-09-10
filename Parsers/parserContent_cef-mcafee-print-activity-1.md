#### Parser Content
```Java
{
Name = cef-mcafee-print-activity-1
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "dlp-alert"
      TimeFormat = "epoch"
      Conditions = [ """McAfee|Data Loss Prevention""", """|dlp """, """cs2Label=Printer Name""" ]
      Fields = [
        """(\s|\|)rt=({time}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)cs2=({printer_name}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)suser=({user}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)fname=({object}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)cs1=({additional_info}.+?)\s+([\w\.-]+=|$)"""
      ]
    }
```
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
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)cs2=({printer_name}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)suser=({user}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)fname=({object}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)cs1=({additional_info}.+?)\s{1,100}([\w\.-]+=|$)"""
      ]
    }
```
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
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)cs2=({printer_name}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)shost=({src_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)src=({src_ip}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)suser=({user}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)sntdom=({domain}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fname=({object}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)cs1=({additional_info}.+?)\s{1,100}([\w\.-]{1,2000}=|$)"""
      ]
    }
```
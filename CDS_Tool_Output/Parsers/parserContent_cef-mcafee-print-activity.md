#### Parser Content
```Java
{
Name = cef-mcafee-print-activity
      Vendor = McAfee
      Product = McAfee DLP
      Lms = ArcSight
      DataType = "print-activity"
      TimeFormat = "epoch"
      Conditions = [ """McAfee|Data Loss Prevention""", """|DLP: Printing Protection|""" ]
      Fields = [
        """(\s|\|)rt=({time}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)cs2=({dest_host}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)cs2=\\+.+?(\\+({printer_name}.+?))\s+([\w\.-]+=|$)""",
        """(\s|\|)dhost=({dest_host}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)dst=({dest_ip}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)duser=({user}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)dntdom=({domain}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)fname=({object}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)({activity}Printing)""",
      ]
    }
```
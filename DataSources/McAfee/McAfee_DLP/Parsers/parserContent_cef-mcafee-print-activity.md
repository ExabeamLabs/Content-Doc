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
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\sCEF:""",
        """(\s|\|)cs2=({dest_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)cs2=\\{1,25}.{1,2000}?(\\{1,25}({printer_name}.{1,2000}?))\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dhost=({dest_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dst=({dest_ip}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)duser=({user}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dntdom=({domain}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fname=({object}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)({activity}Printing)""",
      ]
    }
```
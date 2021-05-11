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
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]+=|$)""",
        """\d\d:\d\d\s{1,100}({host}[^\s]+)\sCEF:""",
        """(\s|\|)cs2=({dest_host}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)cs2=\\+.+?(\\+({printer_name}.+?))\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)dhost=({dest_host}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)dst=({dest_ip}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)duser=({user}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)dntdom=({domain}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)fname=({object}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)({activity}Printing)""",
      ]
    }
```
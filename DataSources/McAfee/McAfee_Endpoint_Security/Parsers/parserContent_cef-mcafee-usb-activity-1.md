#### Parser Content
```Java
{
Name = cef-mcafee-usb-activity-1
      Vendor = McAfee
      Product = McAfee Endpoint Security
      Lms = ArcSight
      DataType = "usb-activity"
      TimeFormat = "epoch"
      Conditions = [ """McAfee|Data Loss Prevention""", """|DLP: Removable Storage Protection|""" ]
      Fields = [
        """(\s|\|)rt=({time}.+?)\s+([\w\.-]+=|$)""",
        """\d\d:\d\d\s+({host}[^\s]+)\sCEF:""",
        """(\s|\|)cs2=({device_type}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)dhost=({dest_host}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)dst=({dest_ip}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)duser=({user}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)dntdom=({domain}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)fname=.+?({file_name}[^\\]+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)filePath=({file_path}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)msg=({activity_detail}.+?)\s+([\w\.-]+=|$)""",
        """(\s|\|)msg=({activity}.+?)\s*([\w\.-]+=|$)""",
        """(\s|\|)msg=.+?to\s+({activity}[^,=]+)(,\s|\s|$)""",
        """(\s|\|)ad\.AppProductName=({process_name}.+?)\s+([\w\.-]+=|$)""",
      ]
    }
```
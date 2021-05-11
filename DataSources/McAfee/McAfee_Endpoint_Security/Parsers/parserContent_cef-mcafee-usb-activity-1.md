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
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]+=|$)""",
        """\d\d:\d\d\s{1,100}({host}[^\s]+)\sCEF:""",
        """(\s|\|)cs2=({device_type}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)dhost=({dest_host}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)dst=({dest_ip}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)duser=({user}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)dntdom=({domain}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)fname=.+?({file_name}[^\\]+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)filePath=({file_path}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)msg=({activity_detail}.+?)\s{1,100}([\w\.-]+=|$)""",
        """(\s|\|)msg=({activity}.+?)\s{0,100}([\w\.-]+=|$)""",
        """(\s|\|)msg=.+?to\s{1,100}({activity}[^,=]+)(,\s|\s|$)""",
        """(\s|\|)ad\.AppProductName=({process_name}.+?)\s{1,100}([\w\.-]+=|$)""",
      ]
    }
```
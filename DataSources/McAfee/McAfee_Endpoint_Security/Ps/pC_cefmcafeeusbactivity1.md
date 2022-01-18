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
        """(\s|\|)rt=({time}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\sCEF:""",
        """(\s|\|)cs2=({device_type}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dhost=({dest_host}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dst=({dest_ip}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)duser=({user}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)dntdom=({domain}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fname=.+?({file_name}[^\\]{1,2000}?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)filePath=({file_path}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)fsize=({bytes}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)msg=({activity_detail}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)msg=({activity}.+?)\s{0,100}([\w\.-]{1,2000}=|$)""",
        """(\s|\|)msg=.+?to\s{1,100}({activity}[^,=]{1,2000})(,\s|\s|$)""",
        """(\s|\|)ad\.AppProductName =({process_name}.+?)\s{1,100}([\w\.-]{1,2000}=|$)""",
      ]
    

}
```
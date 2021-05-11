#### Parser Content
```Java
{
Name = q-trendmicro-epp-alert
  Vendor = Trend Micro
  Product = OfficeScan
  Lms = QRadar
       DataType = "alert"
       TimeFormat = "MM/dd/yyyy HH:mm:ss"
       Conditions = [ "Virus/Malware:" , "Date/Time:" ]
       Fields = [
        """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
        """Computer:\s{1,100}({host}[^\s]+)\s""",
        """Date\/Time:\s{0,100}({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d\d:\d\d:\d\d)""",       
        """Virus/Malware:\s({alert_name}[^\s]+)\s""",
        """Computer:\s{1,100}({src_host}[^\s]+)\s""",
        """IP address:\s{1,100}({src_ip}[^\s]+)\s""",
        """File:\s{1,100}({malware_url}.+?)\s{1,100}Date""",
        """User name:\s({user}[^\s]+)"""
       ]
}
```
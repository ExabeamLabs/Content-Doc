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
        """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
        """Computer:\s+({host}[^\s]+)\s""",
        """Date\/Time:\s*({time}\d+\/\d+\/\d\d\d\d \d\d:\d\d:\d\d)""",       
        """Virus/Malware:\s({alert_name}[^\s]+)\s""",
        """Computer:\s+({src_host}[^\s]+)\s""",
        """IP address:\s+({src_ip}[^\s]+)\s""",
        """File:\s+({malware_url}.+?)\s+Date""",
        """User name:\s({user}[^\s]+)"""
       ]
}
```
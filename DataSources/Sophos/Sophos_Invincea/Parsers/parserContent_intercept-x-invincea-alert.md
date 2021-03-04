#### Parser Content
```Java
{
Name = intercept-x-invincea-alert
  Vendor = Sophos
  Product = Sophos Invincea
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """INVINCEA:""", """vendor=Invincea""", """product=Invincea""" ]
  Fields = [
        """\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+({host}[^\s]+)""",
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
        """\s+name="({alert_name}[^\"]+)""",
        """severity=({alert_severity}\d+)\s+""",
        """src_host=({src_host}[^\s]+)""",
        """src_ip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """product=({alert_type}[^\s]+)""",
        """request=({malware_url}.+?)\s+num_exec""",
        """src_user=({user}.+?)\s+src_host"""
  ]
}
```
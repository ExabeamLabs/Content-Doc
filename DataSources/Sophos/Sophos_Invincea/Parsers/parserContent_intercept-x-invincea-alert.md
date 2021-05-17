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
        """\w{3}\s{1,100}\d{1,2}\s{1,100}\d{2}:\d{2}:\d{2}\s{1,100}({host}[^\s]{1,2000})""",
        """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
        """\s{1,100}name="({alert_name}[^\"]{1,2000})""",
        """severity=({alert_severity}\d{1,100})\s{1,100}""",
        """src_host=({src_host}[^\s]{1,2000})""",
        """src_ip=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """product=({alert_type}[^\s]{1,2000})""",
        """request=({malware_url}.+?)\s{1,100}num_exec""",
        """src_user=({user}.+?)\s{1,100}src_host"""
  ]
  DupFields = ["host->dest_host", "malware_url->process_name"]
}
```
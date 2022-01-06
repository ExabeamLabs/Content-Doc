#### Parser Content
```Java
{
Name = imperva-attack-analytics-network-alert
  Vendor = Imperva
  Product = Attack Analytics
  Lms = Direct
  DataType = "network-alert"
  TimeFormat = "epoch"
  Conditions = [ """|Imperva Inc|""", """|Attack Analytics|""", """CloudWAF""", """ImpervaAAPlatform""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}[^\s]{1,2000})""",
    """start\\?=({time}\d{1,20})""", 
    """cs7\\?=({alert_name}[^=]{1,2000}?)\s{1,10}\w{1,100}\\?=""",
    """({alert_type}Attack Analytics)""",
    """Attack Analytics\|([^|]{0,2000}\|){3}({alert_severity}[^|]{1,2000})\|""",
    """src\\?=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """request\\?=(\/|(?i)Distributed|({uri_path}[^\n]{1,2000}?))\s{1,10}requestClientApplication\\?=((?i)Distributed|({app}[^=]{1,2000}))\s{1,10}\w{1,100}\\?=""",
    """msg\\?=({additional_info}[^\n]{1,2000}?)\s{1,10}start\\?=""",
    """dhost\\?=((?i)Distributed|({target}[^=]{1,2000}))\s{1,10}\w{1,1000}\\?="""
  ]


}
```
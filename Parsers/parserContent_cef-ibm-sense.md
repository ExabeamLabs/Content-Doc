#### Parser Content
```Java
{
Name = cef-ibm-sense
  Vendor = IBM
  Product = IBM Sense
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|IBM|Sense|""", """UBA Machine Learning Anomaly""" ]
  Fields = [
    """usrName=({user}[^\s]+)\s""",
    """senseValue=({sense_value}\d+)\s""",
    """senseScore=({sense_score}[\d.]+)""",
    """startTime=({time}\d+)""",
    """\|IBM\|Sense\|[\d.]+\|({alert_name}[^\|]+)\|""",
    """cat=({alert_type}.+\S)\s+src""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s"""
  ]
}
```
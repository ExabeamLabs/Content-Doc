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
    """usrName=({user}[^\s]{1,2000})\s""",
    """senseValue=({sense_value}\d{1,100})\s""",
    """senseScore=({sense_score}[\d.]{1,2000})""",
    """startTime=({time}\d{1,100})""",
    """\|IBM\|Sense\|[\d.]{1,2000}\|({alert_name}[^\|]{1,2000})\|""",
    """cat=({alert_type}.+\S)\s{1,100}src""",
    """src=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s""",
    """dst=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s"""
  ]
}
```
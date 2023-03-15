#### Parser Content
```Java
{
Name = leef-ibm-sense-alert
  Vendor = IBM
  Product = IBM Sense
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """|IBM|Sense|""", """|UBA Offense - User crossed risk threshold|""" ]
  Fields = [
    """usrName =({user}[^\s\\]{1,2000})""",
    """senseOffenseId=({alert_id}[^=\\]{1,2000}?)(\\|")""",
    """senseOffenseScore=({sense_score}[\d\.]{1,2000})""",
    """startTime=({time}\d{1,100})""",
    """\|IBM\|Sense\|[\d.]{1,2000}\|({alert_name}[^\|]{1,2000})\|""",
    """cat=({alert_type}[^=\\]{1,2000}?)(\\|\susr)""",
    """({event_name}User crossed risk threshold)"""
  ]


}
```
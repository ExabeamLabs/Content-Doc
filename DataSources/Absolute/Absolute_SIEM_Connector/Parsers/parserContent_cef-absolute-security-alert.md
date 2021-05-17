#### Parser Content
```Java
{
Name = cef-absolute-security-alert
  Vendor = Absolute
  Product = Absolute SIEM Connector
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss z"
  Conditions = [ """CEF:""", """|Absolute|AbsoluteSIEMConnector|""", """|Absolute.System.Alerts|""" ]
  Fields = [
    """\Wrt=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d \w+)""",
    """({host}[\w.\-]{1,2000})\s{1,100}CTAlertEvents""",
    """CEF:([^\|]{0,2000}\|){4}({alert_type}[^\|]{1,2000})\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})\|""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcn1=(|({alert_id}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wmsg=(|({additional_info}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```